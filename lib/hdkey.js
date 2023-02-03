/**
 * @typedef HDKey
 * @prop {HDCreate} create
 * @prop {HDFromSeed} fromMasterSeed
 * @prop {HDFromXKey} fromExtendedKey
 * @prop {HDUtils} utils
 * @prop {Number} HARDENED_OFFSET - 0x80000000
 */

/**
 * @typedef HDUtils
 * @prop {HDKeyTweak} privateKeyTweakAdd
 * @prop {HDKeyTweak} publicKeyTweakAdd
 * @prop {HDKeyToKey} publicKeyNormalize
 * @prop {HDHasher} ripemd160sum
 * @prop {HDHasher} sha256sum
 * @prop {HDHasher} sha512hmac
 * @prop {HDKeyToKey} toPublicKey
 */

/**
 * @callback HDCreate
 * @param {HDVersions} [versions]
 * @returns {hdkey}
 */

/**
 * @typedef hdkey
 * @prop {Uint8Array} chainCode - extra 32-bytes of shared entropy for xkeys
 * @prop {Number} depth - of hd path - typically 0 is seed, 1-3 hardened, 4-5 are not
 * @prop {Uint8Array} identifier - same bytes as pubKeyHash, but used for id
 * @prop {Number} index - the final segment of an HD Path, the index of the wif/addr
 * @prop {Number} parentFingerprint - 32-bit int, slice of id, stored in child xkeys
 * @prop {Uint8Array} publicKey
 * @prop {HDVersions} versions - magic bytes for base58 prefix
 * @prop {HDDerivePath} derive - derive a full hd path from the given root
 * @prop {HDDeriveChild} deriveChild - get the next child xkey (in a path segment)
 * @prop {HDFingerprint} getFingerprint
 * @prop {HDMaybeGetString} getPrivateExtendedKey
 * @prop {HDMaybeGetBuffer} getPrivateKey
 * @prop {HDGetString} getPublicExtendedKey
 * @prop {HDSetBuffer} setPublicKey
 * @prop {HDSetBuffer} setPrivateKey
 * @prop {HDWipePrivates} wipePrivateData - randomizes private key buffer in-place
 * @prop {Function} _setPublicKey
 */

/** @type {HDKey} */
//@ts-ignore
var HDKey = ("object" === typeof module && exports) || {};
(function (window, HDKey) {
  "use strict";

  //const BUFFER_LE = true;
  const BUFFER_BE = false;
  const COMPRESSED = true;

  //@ts-ignore
  let Crypto = window.crypto || require("crypto");
  let bs58check = require("bs58check");

  let Utils = {};

  /** @type {HDKeyTweak} */
  Utils.privateKeyTweakAdd = async function (privateKeyCopy, tweak) {
    let Secp256k1 =
      //@ts-ignore
      window.nobleSecp256k1 || require("@dashincubator/secp256k1");
    let p = Secp256k1.utils._normalizePrivateKey(privateKeyCopy);
    let t = Secp256k1.utils._normalizePrivateKey(tweak);
    return Secp256k1.utils._bigintTo32Bytes(
      Secp256k1.utils.mod(p + t, Secp256k1.CURVE.n),
    );
  };

  /** @type {HDKeyToKey} */
  Utils.publicKeyNormalize = async function (pubBytes) {
    let Secp256k1 =
      //@ts-ignore
      window.nobleSecp256k1 || require("@dashincubator/secp256k1");

    try {
      let point = Secp256k1.Point.fromHex(pubBytes);
      pubBytes = point.toRawBytes(COMPRESSED);
    } catch (e) {
      throw new Error("Invalid public key");
    }

    return pubBytes;
  };

  /** @type {HDKeyTweak} */
  Utils.publicKeyTweakAdd = async function (publicKeyCopy, tweak) {
    let Secp256k1 =
      //@ts-ignore
      window.nobleSecp256k1 || require("@dashincubator/secp256k1");

    let P = Secp256k1.Point.fromHex(publicKeyCopy);
    let t = Secp256k1.utils._normalizePrivateKey(tweak);
    let Q = Secp256k1.Point.BASE.multiplyAndAddUnsafe(P, t, 1n);
    if (!Q) {
      throw new Error("Tweaked point at infinity");
    }
    return Q.toRawBytes(COMPRESSED);
  };

  /** @type {HDHasher} */
  Utils.ripemd160sum = async function (bytes) {
    let RIPEMD160 = require("ripemd160");
    let buf = Buffer.from(bytes);
    let hash = new RIPEMD160().update(buf).digest();
    return new Uint8Array(hash);
  };

  /** @type {HDHasher} */
  Utils.sha256sum = async function (bytes) {
    if (!Crypto.subtle) {
      let sha256 = Crypto.createHash("sha256").update(bytes).digest();
      return new Uint8Array(sha256);
    }
    let arrayBuffer = await Crypto.subtle.digest("SHA-256", bytes);
    let hashBytes = new Uint8Array(arrayBuffer);
    return hashBytes;
  };

  /** @type {HDHmac} */
  Utils.sha512hmac = async function (entropy, data) {
    if (!Crypto.subtle) {
      let buf = Crypto.createHmac("sha512", entropy).update(data).digest();
      return new Uint8Array(buf);
    }

    /** @type {"raw"|"pkcs8"|"spki"} */
    let format = "raw";
    let algo = {
      name: "HMAC",
      hash: "SHA-512",
    };
    let extractable = false;
    /** @type {Array<KeyUsage>} */
    let keyUsages = ["sign"];
    let hmacKey = await Crypto.subtle.importKey(
      format,
      entropy,
      algo,
      extractable,
      keyUsages,
    );
    let sig = await Crypto.subtle.sign("HMAC", hmacKey, data);

    return new Uint8Array(sig);
  };

  /** @type {HDSecureErase} */
  Utils.secureErase = function (buf) {
    if (!Crypto.getRandomValues) {
      Crypto.randomBytes(buf.length).copy(buf);
      return;
    }

    Crypto.getRandomValues(buf);
  };

  /** @type {HDKeyToKey} */
  Utils.toPublicKey = async function (privBytes) {
    let Secp256k1 =
      //@ts-ignore
      window.nobleSecp256k1 || require("@dashincubator/secp256k1");

    return Secp256k1.getPublicKey(privBytes, COMPRESSED);
  };

  // "Bitcoin seed"
  let MASTER_SECRET = Uint8Array.from([
    // B     i     t     c     o     i     n   " "     s     e     e     d
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
  ]);
  let HARDENED_OFFSET = 0x80000000;
  let KEY_SIZE = 33;
  let INDEXED_KEY_SIZE = 4 + KEY_SIZE;
  let XKEY_SIZE = 78;

  // Bitcoin hardcoded by default, can use package `coininfo` for others
  let BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

  HDKey.create = function (versions) {
    /** @type {hdkey} */
    let hdkey = {};
    /** @type {Uint8Array?} */
    let _privateKey = null;

    hdkey.versions = versions || BITCOIN_VERSIONS;
    hdkey.depth = 0;
    hdkey.index = 0;
    //hdkey.publicKey = null;
    //hdkey.identifier = null;
    //hdkey.chainCode = null;
    hdkey.parentFingerprint = 0;

    hdkey.getFingerprint = function () {
      if (!hdkey.identifier) {
        throw new Error("Public key has not been set");
      }
      let i32be = readUInt32BE(hdkey.identifier, 0);
      return i32be;
    };

    /**
     * @param {Uint8Array} u8 - a "web" JS buffer
     * @param {Number} offset - where to start reading
     * @returns {Number} - a 0-shifted (uint) JS Number
     */
    function readUInt32BE(u8, offset) {
      let dv = new DataView(u8.buffer);
      // will read offset + 4 bytes (32-bit uint)
      let n = dv.getUint32(offset, BUFFER_BE);
      return n;
    }

    hdkey.getPrivateKey = function () {
      return _privateKey;
    };
    hdkey.setPrivateKey = async function (value) {
      assert(value.length === 32, "Private key must be 32 bytes.");

      _privateKey = value;
      hdkey.publicKey = await Utils.toPublicKey(value);
      hdkey.identifier = await hash160(hdkey.publicKey);
    };

    hdkey.setPublicKey = async function (value) {
      assert(
        value.length === 33 || value.length === 65,
        "Public key must be 33 or 65 bytes.",
      );
      let publicKey = await Utils.publicKeyNormalize(value);
      await hdkey._setPublicKey(publicKey);
    };

    /**
     * @param {Uint8Array} publicKey
     */
    hdkey._setPublicKey = async function (publicKey) {
      hdkey.publicKey = publicKey;
      hdkey.identifier = await hash160(publicKey);
      _privateKey = null;
    };

    hdkey.getPrivateExtendedKey = async function () {
      if (!_privateKey) {
        return null;
      }

      let key = new Uint8Array(KEY_SIZE);
      key.set([0], 0);
      key.set(_privateKey, 1);
      return await bs58check.encode(
        serialize(hdkey, hdkey.versions.private, key),
      );
    };

    hdkey.getPublicExtendedKey = async function () {
      if (!hdkey.publicKey) {
        throw new Error("Missing public key");
      }

      return await bs58check.encode(
        serialize(hdkey, hdkey.versions.public, hdkey.publicKey),
      );
    };

    hdkey.derive = async function (path) {
      if (path === "m" || path === "M" || path === "m'" || path === "M'") {
        return hdkey;
      }

      let entries = path.split("/");
      let _hdkey = hdkey;
      for (let i = 0; i < entries.length; i += 1) {
        let c = entries[i];
        if (i === 0) {
          assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
          continue;
        }

        let hardened = c.length > 1 && c[c.length - 1] === "'";
        let childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
        assert(childIndex < HARDENED_OFFSET, "Invalid index");
        if (hardened) {
          childIndex += HARDENED_OFFSET;
        }

        _hdkey = await _hdkey.deriveChild(childIndex);
      }

      return _hdkey;
    };

    // IMPORTANT: never allow `await` (or other async) between writing to
    // and accessing these! (otherwise the data will be corrupted)
    // (stored here for performance - no allocations or garbage collection)
    let _indexBuffer = new Uint8Array(4);
    let _indexDv = new DataView(_indexBuffer.buffer);

    hdkey.deriveChild = async function (index) {
      let isHardened = index >= HARDENED_OFFSET;
      let offset = 0;
      _indexDv.setUint32(offset, index, BUFFER_BE);

      let data = new Uint8Array(INDEXED_KEY_SIZE);

      if (isHardened) {
        // Hardened child
        if (!_privateKey) {
          throw new Error("Could not derive hardened child key");
        }

        // data = 0x00 || ser256(kpar) || ser32(index)
        data.set([0], 0); // 1
        data.set(_privateKey, 1); // 32
        data.set(_indexBuffer, KEY_SIZE);
      } else {
        // Normal child
        // data = serP(point(kpar)) || ser32(index)
        //      = serP(Kpar) || ser32(index)
        data.set(hdkey.publicKey, 0);
        data.set(_indexBuffer, KEY_SIZE);
      }

      let IBuf = await Utils.sha512hmac(hdkey.chainCode, data);
      let I = new Uint8Array(IBuf);
      let IL = I.slice(0, 32);
      let IR = I.slice(32);

      let hd = HDKey.create(hdkey.versions);

      // Private parent key -> private child key
      if (_privateKey) {
        // ki = parse256(IL) + kpar (mod n)
        try {
          let privateKeyCopy = new Uint8Array(_privateKey);
          await hd.setPrivateKey(
            await Utils.privateKeyTweakAdd(privateKeyCopy, IL),
          );
          // throw if IL >= n || (privateKey + IL) === 0
        } catch (err) {
          // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
          return await hdkey.deriveChild(index + 1);
        }
        // Public parent key -> public child key
      } else {
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        try {
          let publicKeyCopy = new Uint8Array(hdkey.publicKey);
          await hd.setPublicKey(
            await Utils.publicKeyTweakAdd(publicKeyCopy, IL),
          );
          // throw if IL >= n || (g**IL + publicKey) is infinity
        } catch (err) {
          // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
          return await hdkey.deriveChild(index + 1);
        }
      }

      hd.chainCode = IR;
      hd.depth = hdkey.depth + 1;
      hd.parentFingerprint = hdkey.getFingerprint();
      hd.index = index;

      return hd;
    };

    hdkey.wipePrivateData = function () {
      if (_privateKey) {
        Utils.secureErase(_privateKey);
      }
      _privateKey = null;
      return hdkey;
    };

    return hdkey;
  };

  HDKey.fromMasterSeed = async function (seedBuffer, versions) {
    let IBuf = await Utils.sha512hmac(MASTER_SECRET, seedBuffer);
    let I = new Uint8Array(IBuf);
    let IL = I.subarray(0, 32);
    let IR = I.subarray(32);

    let hdkey = HDKey.create(versions);
    hdkey.chainCode = IR;
    await hdkey.setPrivateKey(IL);

    return hdkey;
  };

  HDKey.fromExtendedKey = async function (
    base58key,
    versions,
    skipVerification,
  ) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    versions = versions || BITCOIN_VERSIONS;
    skipVerification = skipVerification || false;
    let hdkey = HDKey.create(versions);

    let keyBuffer = bs58check.decode(base58key);
    let keyU8 = new Uint8Array(keyBuffer);
    let keyDv = new DataView(keyU8.buffer, 0, keyU8.byteLength);

    let version = keyDv.getUint32(0, BUFFER_BE);
    assert(
      version === versions.private || version === versions.public,
      "Version mismatch: does not match private or public",
    );

    hdkey.depth = keyDv.getUint8(4);
    hdkey.parentFingerprint = keyDv.getUint32(5, BUFFER_BE);
    hdkey.index = keyDv.getUint32(9, BUFFER_BE);
    hdkey.chainCode = keyU8.subarray(13, 45);

    let key = keyU8.subarray(45);
    if (keyDv.getUint8(45) === 0) {
      // private
      assert(
        version === versions.private,
        "Version mismatch: version does not match private",
      );
      await hdkey.setPrivateKey(key.subarray(1)); // cut off first 0x0 byte
    } else {
      assert(
        version === versions.public,
        "Version mismatch: version does not match public",
      );
      if (skipVerification) {
        await hdkey._setPublicKey(key);
      } else {
        await hdkey.setPublicKey(key);
      }
    }

    return hdkey;
  };

  /**
   * @param {Boolean} assertion
   * @param {String} message
   */
  function assert(assertion, message) {
    if (!assertion) {
      throw new Error(message);
    }
  }

  /**
   * @param {hdkey} hdkey - TODO attach to hdkey
   * @param {Number} version
   * @param {Uint8Array} key
   */
  function serialize(hdkey, version, key) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    let xkey = new Uint8Array(XKEY_SIZE);
    let xkeyDv = new DataView(xkey.buffer);

    xkeyDv.setUint32(0, version, BUFFER_BE);
    xkeyDv.setUint8(4, hdkey.depth);

    let fingerprint = (hdkey.depth && hdkey.parentFingerprint) || 0x00000000;
    xkeyDv.setUint32(5, fingerprint, BUFFER_BE);
    xkeyDv.setUint32(9, hdkey.index, BUFFER_BE);

    xkey.set(hdkey.chainCode, 13);
    xkey.set(key, 45);

    return xkey;
  }

  /**
   * @param {Uint8Array} buf
   * @returns {Promise<Uint8Array>}
   */
  async function hash160(buf) {
    let sha = await Utils.sha256sum(buf);
    return await Utils.ripemd160sum(sha);
  }

  HDKey.HARDENED_OFFSET = HARDENED_OFFSET;
})(("object" === typeof window && window) || {}, HDKey);
if ("object" === typeof module) {
  module.exports = HDKey;
}

// Type Definitions

/**
 * @typedef HDVersions
 * @prop {Number} private - 32-bit (4-byte) int (encodes to 'xprv' in base58)
 * @prop {Number} public - 32-bit (4-byte) int (encodes to 'xpub' in base58)
 */

// Function Definitions

/**
 * @callback HDDeriveChild
 * @param {Number} index - includes HARDENED_OFFSET, if applicable
 * returns {Promise<hdkey>}
 */

/**
 * @callback HDDerivePath
 * @param {String} path
 * returns {Promise<hdkey>}
 */

/**
 * @callback HDFingerprint
 * @returns {Number}
 */

/**
 * @callback HDFromXKey
 * @param {String} base58key - base58check-encoded xkey
 * @param {HDVersions} [versions]
 * @param {Boolean} [skipVerification]
 * returns {Promise<hdkey>}
 */

/**
 * @callback HDFromSeed
 * @param {Uint8Array} seedBuffer
 * @param {HDVersions} [versions]
 * @returns {Promise<hdkey>}
 */

/**
 * @callback HDGetBuffer
 * @returns {Uint8Array}
 */

/**
 * @callback HDGetString
 * @returns {Promise<String>}
 */

/**
 * @callback HDHasher
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>} - hash Uint8Array
 */

/**
 * @callback HDHmac
 * @param {Uint8Array} entropy - secret, salt, or key
 * @param {Uint8Array} data - message
 * @returns {Promise<Uint8Array>} - hash Uint8Array
 */

/**
 * @callback HDKeyToKey
 * @param {Uint8Array} keyBytes - Key Uint8Array
 * @returns {Promise<Uint8Array>} - Public Key Uint8Array
 */

/**
 * @callback HDKeyTweak
 * @param {Uint8Array} keyBytes - Key Uint8Array
 * @param {Uint8Array} tweakBytes - Tweak Uint8Array
 * @returns {Promise<Uint8Array>} - Public Key Uint8Array
 */

/**
 * @callback HDMaybeGetBuffer
 * @returns {Uint8Array?}
 */

/**
 * @callback HDMaybeGetString
 * @returns {Promise<String?>}
 */

/**
 * @callback HDSecureErase
 * @param {Uint8Array} buf
 * @returns {void}
 */

/**
 * @callback HDSetBuffer
 * @param {Uint8Array} buf
 */

/**
 * @callback HDWipePrivates
 */
