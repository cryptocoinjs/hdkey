var HDKey = ("object" === typeof module && exports) || {};
(function (window, HDKey) {
  "use strict";

  var crypto = require("crypto");
  var bs58check = require("bs58check");
  var RIPEMD160 = require("ripemd160");
  var secp256k1 = require("secp256k1");

  var MASTER_SECRET = Buffer.from("Bitcoin seed", "utf8");
  var HARDENED_OFFSET = 0x80000000;
  var LEN = 78;

  // Bitcoin hardcoded by default, can use package `coininfo` for others
  var BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

  HDKey.create = function (versions) {
    var hdkey = {};
    var _privateKey = null;

    hdkey.versions = versions || BITCOIN_VERSIONS;
    hdkey.depth = 0;
    hdkey.index = 0;
    hdkey.publicKey = null;
    // note: BIP-32 "Key Identifier" is the same as "Pub Key Hash"
    // but used for a different purpose, hence the semantic name
    hdkey.identifier = null;
    // note: chainCode is public
    hdkey.chainCode = null;
    hdkey.parentFingerprint = 0;

    hdkey.getFingerprint = function () {
      return hdkey.identifier.slice(0, 4).readUInt32BE(0);
    };

    hdkey.getPrivateKey = function () {
      return _privateKey;
    };
    hdkey.setPrivateKey = function (value) {
      assert(value.length === 32, "Private key must be 32 bytes.");
      assert(secp256k1.privateKeyVerify(value) === true, "Invalid private key");

      _privateKey = value;
      hdkey.publicKey = Buffer.from(secp256k1.publicKeyCreate(value, true));
      hdkey.identifier = hash160(hdkey.publicKey);
    };

    hdkey.setPublicKey = function (value) {
      assert(
        value.length === 33 || value.length === 65,
        "Public key must be 33 or 65 bytes.",
      );
      assert(secp256k1.publicKeyVerify(value) === true, "Invalid public key");
      // force compressed point (performs public key verification)
      var publicKey =
        value.length === 65 ? secp256k1.publicKeyConvert(value, true) : value;
      hdkey._setPublicKey(publicKey);
    };

    hdkey._setPublicKey = function (publicKey) {
      hdkey.publicKey = Buffer.from(publicKey);
      hdkey.identifier = hash160(publicKey);
      _privateKey = null;
    };

    hdkey.getPrivateExtendedKey = function () {
      if (!_privateKey) {
        return null;
      }

      return bs58check.encode(
        serialize(
          hdkey,
          hdkey.versions.private,
          Buffer.concat([Buffer.alloc(1, 0), _privateKey]),
        ),
      );
    };

    hdkey.getPublicExtendedKey = function () {
      return bs58check.encode(
        serialize(hdkey, hdkey.versions.public, hdkey.publicKey),
      );
    };

    hdkey.derive = function (path) {
      if (path === "m" || path === "M" || path === "m'" || path === "M'") {
        return hdkey;
      }

      var entries = path.split("/");
      var _hdkey = hdkey;
      entries.forEach(function (c, i) {
        if (i === 0) {
          assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
          return;
        }

        var hardened = c.length > 1 && c[c.length - 1] === "'";
        var childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
        assert(childIndex < HARDENED_OFFSET, "Invalid index");
        if (hardened) {
          childIndex += HARDENED_OFFSET;
        }

        _hdkey = _hdkey.deriveChild(childIndex);
      });

      return _hdkey;
    };

    hdkey.deriveChild = function (index) {
      var isHardened = index >= HARDENED_OFFSET;
      var indexBuffer = Buffer.allocUnsafe(4);
      indexBuffer.writeUInt32BE(index, 0);

      var data;

      if (isHardened) {
        // Hardened child
        assert(Boolean(_privateKey), "Could not derive hardened child key");

        var pk = _privateKey;
        var zb = Buffer.alloc(1, 0);
        pk = Buffer.concat([zb, pk]);

        // data = 0x00 || ser256(kpar) || ser32(index)
        data = Buffer.concat([pk, indexBuffer]);
      } else {
        // Normal child
        // data = serP(point(kpar)) || ser32(index)
        //      = serP(Kpar) || ser32(index)
        data = Buffer.concat([hdkey.publicKey, indexBuffer]);
      }

      var I = crypto
        .createHmac("sha512", hdkey.chainCode)
        .update(data)
        .digest();
      var IL = I.slice(0, 32);
      var IR = I.slice(32);

      var hd = HDKey.create(hdkey.versions);

      // Private parent key -> private child key
      if (_privateKey) {
        // ki = parse256(IL) + kpar (mod n)
        try {
          hd.setPrivateKey(
            Buffer.from(
              secp256k1.privateKeyTweakAdd(Buffer.from(_privateKey), IL),
            ),
          );
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
          hd.setPublicKey(
            Buffer.from(
              secp256k1.publicKeyTweakAdd(
                Buffer.from(hdkey.publicKey),
                IL,
                true,
              ),
            ),
          );
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
      return Buffer.from(
        secp256k1.ecdsaSign(Uint8Array.from(hash), Uint8Array.from(_privateKey))
          .signature,
      );
    };

    hdkey.verify = function (hash, signature) {
      return secp256k1.ecdsaVerify(
        Uint8Array.from(signature),
        Uint8Array.from(hash),
        Uint8Array.from(hdkey.publicKey),
      );
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
    var I = crypto
      .createHmac("sha512", MASTER_SECRET)
      .update(seedBuffer)
      .digest();
    var IL = I.slice(0, 32);
    var IR = I.slice(32);

    var hdkey = HDKey.create(versions);
    hdkey.chainCode = IR;
    hdkey.setPrivateKey(IL);

    return hdkey;
  };

  HDKey.fromExtendedKey = function (base58key, versions, skipVerification) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    versions = versions || BITCOIN_VERSIONS;
    skipVerification = skipVerification || false;
    var hdkey = HDKey.create(versions);

    var keyBuffer = bs58check.decode(base58key);

    var version = keyBuffer.readUInt32BE(0);
    assert(
      version === versions.private || version === versions.public,
      "Version mismatch: does not match private or public",
    );

    hdkey.depth = keyBuffer.readUInt8(4);
    hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
    hdkey.index = keyBuffer.readUInt32BE(9);
    hdkey.chainCode = keyBuffer.slice(13, 45);

    var key = keyBuffer.slice(45);
    if (key.readUInt8(0) === 0) {
      // private
      assert(
        version === versions.private,
        "Version mismatch: version does not match private",
      );
      hdkey.setPrivateKey(key.slice(1)); // cut off first 0x0 byte
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

  function assert(assertion, message) {
    if (!assertion) {
      throw new Error(message);
    }
  }

  function serialize(hdkey, version, key) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    var buffer = Buffer.allocUnsafe(LEN);

    buffer.writeUInt32BE(version, 0);
    buffer.writeUInt8(hdkey.depth, 4);

    var fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000;
    buffer.writeUInt32BE(fingerprint, 5);
    buffer.writeUInt32BE(hdkey.index, 9);

    hdkey.chainCode.copy(buffer, 13);
    key.copy(buffer, 45);

    return buffer;
  }

  function hash160(buf) {
    var sha = crypto.createHash("sha256").update(buf).digest();
    return new RIPEMD160().update(sha).digest();
  }

  HDKey.HARDENED_OFFSET = HARDENED_OFFSET;
})(("object" === typeof window && window) || {}, HDKey);
if ("object" === typeof module) {
  module.exports = HDKey;
}
