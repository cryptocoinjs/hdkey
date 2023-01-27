/**
 * @typedef HDKey
 * @prop {HDCreate} create
 * @prop {HDFromSeed} fromMasterSeed
 * @prop {HDFromXKey} fromExtendedKey
 * @prop {HDFromJSON} fromJSON
 * @prop {Number} HARDENED_OFFSET - 0x80000000
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
 * @prop {HDSign} sign
 * @prop {HDVerify} verify
 * @prop {HDToJSON} toJSON
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

  let crypto = require("crypto");
  let bs58check = require("bs58check");
  let RIPEMD160 = require("ripemd160");
  let secp256k1 = require("secp256k1");

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
    hdkey.setPrivateKey = function (value) {
      assert(value.length === 32, "Private key must be 32 bytes.");
      assert(secp256k1.privateKeyVerify(value) === true, "Invalid private key");

      _privateKey = value;
      hdkey.publicKey = secp256k1.publicKeyCreate(value, true);
      hdkey.identifier = hash160(hdkey.publicKey);
    };

    hdkey.setPublicKey = function (value) {
      assert(
        value.length === 33 || value.length === 65,
        "Public key must be 33 or 65 bytes.",
      );
      assert(secp256k1.publicKeyVerify(value) === true, "Invalid public key");
      // force compressed point (performs public key verification)
      let publicKey =
        value.length === 65 ? secp256k1.publicKeyConvert(value, true) : value;
      hdkey._setPublicKey(publicKey);
    };

    /**
     * @param {Uint8Array} publicKey
     */
    hdkey._setPublicKey = function (publicKey) {
      hdkey.publicKey = publicKey;
      hdkey.identifier = hash160(publicKey);
      _privateKey = null;
    };

    hdkey.getPrivateExtendedKey = function () {
      if (!_privateKey) {
        return null;
      }

      let key = new Uint8Array(KEY_SIZE);
      key.set([0], 0);
      key.set(_privateKey, 1);
      return bs58check.encode(serialize(hdkey, hdkey.versions.private, key));
    };

    hdkey.getPublicExtendedKey = function () {
      if (!hdkey.publicKey) {
        throw new Error("Missing public key");
      }

      return bs58check.encode(
        serialize(hdkey, hdkey.versions.public, hdkey.publicKey),
      );
    };

    hdkey.derive = function (path) {
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

        _hdkey = _hdkey.deriveChild(childIndex);
      }

      return _hdkey;
    };

    // IMPORTANT: never allow `await` (or other async) between writing to
    // and accessing these! (otherwise the data will be corrupted)
    // (stored here for performance - no allocations or garbage collection)
    let _indexBuffer = new Uint8Array(4);
    let _indexDv = new DataView(_indexBuffer.buffer);

    hdkey.deriveChild = function (index) {
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

      let IBuf = crypto
        .createHmac("sha512", hdkey.chainCode)
        .update(data)
        .digest();
      let I = new Uint8Array(IBuf);
      let IL = I.slice(0, 32);
      let IR = I.slice(32);

      let hd = HDKey.create(hdkey.versions);

      // Private parent key -> private child key
      if (_privateKey) {
        // ki = parse256(IL) + kpar (mod n)
        try {
          let privateKeyCopy = new Uint8Array(_privateKey);
          hd.setPrivateKey(secp256k1.privateKeyTweakAdd(privateKeyCopy, IL));
          // throw if IL >= n || (privateKey + IL) === 0
        } catch (err) {
          // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
          return hdkey.deriveChild(index + 1);
        }
        // Public parent key -> public child key
      } else {
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        try {
          let publicKeyCopy = new Uint8Array(hdkey.publicKey);
          hd.setPublicKey(secp256k1.publicKeyTweakAdd(publicKeyCopy, IL, true));
          // throw if IL >= n || (g**IL + publicKey) is infinity
        } catch (err) {
          // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
          return hdkey.deriveChild(index + 1);
        }
      }

      hd.chainCode = IR;
      hd.depth = hdkey.depth + 1;
      hd.parentFingerprint = hdkey.getFingerprint();
      hd.index = index;

      return hd;
    };

    hdkey.sign = function (hash) {
      if (!_privateKey) {
        throw new Error("Private Key must be set");
      }

      return secp256k1.ecdsaSign(hash, _privateKey).signature;
    };

    hdkey.verify = function (hash, signature) {
      return secp256k1.ecdsaVerify(signature, hash, hdkey.publicKey);
    };

    hdkey.wipePrivateData = function () {
      if (_privateKey) {
        crypto.randomBytes(_privateKey.length).copy(_privateKey);
      }
      _privateKey = null;
      return hdkey;
    };

    hdkey.toJSON = function () {
      return {
        xpriv: hdkey.getPrivateExtendedKey(),
        xpub: hdkey.getPublicExtendedKey(),
      };
    };

    return hdkey;
  };

  HDKey.fromMasterSeed = function (seedBuffer, versions) {
    let IBuf = crypto
      .createHmac("sha512", MASTER_SECRET)
      .update(seedBuffer)
      .digest();
    let I = new Uint8Array(IBuf);
    let IL = I.subarray(0, 32);
    let IR = I.subarray(32);

    let hdkey = HDKey.create(versions);
    hdkey.chainCode = IR;
    hdkey.setPrivateKey(IL);

    return hdkey;
  };

  HDKey.fromExtendedKey = function (base58key, versions, skipVerification) {
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
      hdkey.setPrivateKey(key.subarray(1)); // cut off first 0x0 byte
    } else {
      assert(
        version === versions.public,
        "Version mismatch: version does not match public",
      );
      if (skipVerification) {
        hdkey._setPublicKey(key);
      } else {
        hdkey.setPublicKey(key);
      }
    }

    return hdkey;
  };

  HDKey.fromJSON = function (obj) {
    return HDKey.fromExtendedKey(obj.xpriv);
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
   * @returns {Uint8Array}
   */
  function hash160(buf) {
    let sha = crypto.createHash("sha256").update(buf).digest();
    return new RIPEMD160().update(sha).digest();
  }

  HDKey.HARDENED_OFFSET = HARDENED_OFFSET;
})(("object" === typeof window && window) || {}, HDKey);
if ("object" === typeof module) {
  module.exports = HDKey;
}

// Type Definitions

/**
 * @typedef HDVersions
 * @prop {Number} private - 32-bit int (encodes to 'xprv' in base58)
 * @prop {Number} public - 32-bit int (encodes to 'xpub' in base58)
 */

/**
 * @typedef HDJSON
 * @prop {String?} xpriv - base58check-encoded extended private key
 * @prop {String} xpub - base58check-encoded extended public key
 */

// Function Definitions

/**
 * @callback HDDeriveChild
 * @param {Number} index - includes HARDENED_OFFSET, if applicable
 */

/**
 * @callback HDDerivePath
 * @param {String} path
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
 * returns {hdkey}
 */

/**
 * @callback HDFromJSON
 * @param {HDFromJSONOpts} opts
 * returns {hdkey}
 *
 * @typedef HDFromJSONOpts
 * @prop {String} xpriv
 */

/**
 * @callback HDFromSeed
 * @param {Uint8Array} seedBuffer
 * @param {HDVersions} [versions]
 */

/**
 * @callback HDGetBuffer
 * @returns {Uint8Array}
 */

/**
 * @callback HDGetString
 * @returns {String}
 */

/**
 * @callback HDMaybeGetBuffer
 * @returns {Uint8Array?}
 */

/**
 * @callback HDMaybeGetString
 * @returns {String?}
 */

/**
 * @callback HDSetBuffer
 * @param {Uint8Array} buf
 */

/**
 * @callback HDSign
 * @param {Uint8Array} hash
 * @returns {Uint8Array} - signature
 */

/**
 * @callback HDToJSON
 * @returns {HDJSON}
 */

/**
 * @callback HDVerify
 * @param {Uint8Array} hash
 * @param {Uint8Array} signature
 * @returns {Boolean}
 */

/**
 * @callback HDWipePrivates
 */
