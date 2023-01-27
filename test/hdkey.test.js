"use strict";

var assert = require("assert");
var BigInteger = require("bigi");
var crypto = require("crypto");
var ecurve = require("ecurve");
var curve = ecurve.getCurveByName("secp256k1");
var HDKey = require("../");
var fixtures = require("./fixtures/hdkey");

// trinity: mocha
/* global describe it */

describe("hdkey", function () {
  describe("+ fromMasterSeed", function () {
    fixtures.valid.forEach(function (f) {
      it("should properly derive the chain path: " + f.path, function () {
        var hdkey = HDKey.fromMasterSeed(hexToU8(f.seed));
        var childkey = hdkey.derive(f.path);

        assert.equal(childkey.getPrivateExtendedKey(), f.private);
        assert.equal(childkey.getPublicExtendedKey(), f.public);
      });

      describe("> " + f.path + " toJSON() / fromJSON()", function () {
        it("should return an object read for JSON serialization", function () {
          var hdkey = HDKey.fromMasterSeed(hexToU8(f.seed));
          var childkey = hdkey.derive(f.path);

          var obj = {
            xpriv: f.private,
            xpub: f.public,
          };

          assert.deepEqual(childkey.toJSON(), obj);

          var newKey = HDKey.fromJSON(obj);
          assert.strictEqual(newKey.getPrivateExtendedKey(), f.private);
          assert.strictEqual(newKey.getPublicExtendedKey(), f.public);
        });
      });
    });
  });

  describe("- privateKey", function () {
    it("should throw an error if incorrect key size", function () {
      var hdkey = HDKey.create();
      assert.throws(function () {
        hdkey.setPrivateKey(Uint8Array.from([1, 2, 3, 4]));
      }, /key must be 32/);
    });
  });

  describe("- publicKey", function () {
    it("should throw an error if incorrect key size", function () {
      assert.throws(function () {
        var hdkey = HDKey.create();
        hdkey.setPublicKey(Uint8Array.from([1, 2, 3, 4]));
      }, /key must be 33 or 65/);
    });

    it("should not throw if key is 33 bytes (compressed)", function () {
      var rnd = crypto.randomBytes(32);
      var priv = new Uint8Array(rnd);

      var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(true);
      assert.equal(pub.length, 33);
      var hdkey = HDKey.create();
      hdkey.setPublicKey(new Uint8Array(pub));
    });

    it("should not throw if key is 65 bytes (not compressed)", function () {
      var rnd = crypto.randomBytes(32);
      var priv = new Uint8Array(rnd);

      var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(false);
      assert.equal(pub.length, 65);
      var hdkey = HDKey.create();
      hdkey.setPublicKey(new Uint8Array(pub));
    });
  });

  describe("+ fromExtendedKey()", function () {
    describe("> when private", function () {
      it("should parse it", function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
        var hdkey = HDKey.fromExtendedKey(key);
        assert.equal(hdkey.versions.private, 0x0488ade4);
        assert.equal(hdkey.versions.public, 0x0488b21e);
        assert.equal(hdkey.depth, 5);
        assert.equal(hdkey.parentFingerprint, 0x31a507b8);
        assert.equal(hdkey.index, 2);
        assert.equal(
          u8ToHex(hdkey.chainCode),
          "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
        );
        assert.equal(
          u8ToHex(hdkey.getPrivateKey()),
          "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
        );
        assert.equal(
          u8ToHex(hdkey.publicKey),
          "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
        );
        assert.equal(
          u8ToHex(hdkey.identifier),
          "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220",
        );
      });
    });

    describe("> when public", function () {
      it("should parse it", function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
        var hdkey = HDKey.fromExtendedKey(key);
        assert.equal(hdkey.versions.private, 0x0488ade4);
        assert.equal(hdkey.versions.public, 0x0488b21e);
        assert.equal(hdkey.depth, 5);
        assert.equal(hdkey.parentFingerprint, 0x31a507b8);
        assert.equal(hdkey.index, 2);
        assert.equal(
          u8ToHex(hdkey.chainCode),
          "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
        );
        assert.equal(hdkey.getPrivateKey(), null);
        assert.equal(
          u8ToHex(hdkey.publicKey),
          "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
        );
        assert.equal(
          u8ToHex(hdkey.identifier),
          "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220",
        );
      });

      it("should parse it without verification", function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
        var hdkey = HDKey.fromExtendedKey(key, null, false);
        assert.equal(hdkey.versions.private, 0x0488ade4);
        assert.equal(hdkey.versions.public, 0x0488b21e);
        assert.equal(hdkey.depth, 5);
        assert.equal(hdkey.parentFingerprint, 0x31a507b8);
        assert.equal(hdkey.index, 2);
        assert.equal(
          u8ToHex(hdkey.chainCode),
          "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
        );
        assert.equal(hdkey.getPrivateKey(), null);
        assert.equal(
          u8ToHex(hdkey.publicKey),
          "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
        );
        assert.equal(
          u8ToHex(hdkey.identifier),
          "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220",
        );
      });
    });
  });

  describe("> when signing", function () {
    it("should work", function () {
      var key =
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
      var hdkey = HDKey.fromExtendedKey(key);

      var ma = new Uint8Array(32);
      var mb = new Uint8Array(Buffer.alloc(32, 8));
      var a = hdkey.sign(ma);
      var b = hdkey.sign(mb);
      assert.equal(
        u8ToHex(a),
        "6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06",
      );
      assert.equal(
        u8ToHex(b),
        "dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381",
      );
      assert.equal(hdkey.verify(ma, a), true);
      assert.equal(hdkey.verify(mb, b), true);
      assert.equal(hdkey.verify(new Uint8Array(32), new Uint8Array(64)), false);
      assert.equal(hdkey.verify(ma, b), false);
      assert.equal(hdkey.verify(mb, a), false);

      assert.throws(function () {
        hdkey.verify(new Uint8Array(99), a);
      }, /message.*length/);
      assert.throws(function () {
        hdkey.verify(ma, new Uint8Array(99));
      }, /signature.*length/);
    });
  });

  describe("> when deriving public key", function () {
    it("should work", function () {
      var key =
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
      var hdkey = HDKey.fromExtendedKey(key);

      var path = "m/3353535/2223/0/99424/4/33";
      var derivedHDKey = hdkey.derive(path);

      var expected =
        "xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1";
      assert.equal(derivedHDKey.getPublicExtendedKey(), expected);
    });
  });

  describe("> when private key integer is less than 32 bytes", function () {
    it("should work", function () {
      var seed = "000102030405060708090a0b0c0d0e0f";
      var masterKey = HDKey.fromMasterSeed(hexToU8(seed));

      var newKey = masterKey.derive("m/44'/6'/4'");
      var expected =
        "xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx";
      assert.equal(newKey.getPrivateExtendedKey(), expected);
    });
  });

  describe("HARDENED_OFFSET", function () {
    it("should be set", function () {
      assert(HDKey.HARDENED_OFFSET);
    });
  });

  describe("> when private key has leading zeros", function () {
    it("will include leading zeros when hashing to derive child", function () {
      var key =
        "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr";
      var hdkey = HDKey.fromExtendedKey(key);
      assert.equal(
        u8ToHex(hdkey.getPrivateKey()),
        "00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd",
      );
      var derived = hdkey.derive("m/44'/0'/0'/0/0'");
      assert.equal(
        u8ToHex(derived.getPrivateKey()),
        "3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb",
      );
    });
  });

  describe("> when private key is null", function () {
    it("privateExtendedKey should return null and not throw", function () {
      var seed = "000102030405060708090a0b0c0d0e0f";
      var masterKey = HDKey.fromMasterSeed(hexToU8(seed));

      assert.ok(masterKey.getPrivateExtendedKey(), "xpriv is truthy");
      masterKey.wipePrivateData();

      assert.doesNotThrow(function () {
        masterKey.getPrivateExtendedKey();
      });

      assert.ok(!masterKey.getPrivateExtendedKey(), "xpriv is falsy");
    });
  });

  describe(" - when the path given to derive contains only the master extended key", function () {
    const hdKeyInstance = HDKey.fromMasterSeed(hexToU8(fixtures.valid[0].seed));

    it("should return the same hdkey instance", function () {
      assert.equal(hdKeyInstance.derive("m"), hdKeyInstance);
      assert.equal(hdKeyInstance.derive("M"), hdKeyInstance);
      assert.equal(hdKeyInstance.derive("m'"), hdKeyInstance);
      assert.equal(hdKeyInstance.derive("M'"), hdKeyInstance);
    });
  });

  describe(" - when the path given to derive does not begin with master extended key", function () {
    it("should throw an error", function () {
      assert.throws(function () {
        const hdkey = HDKey.create();
        hdkey.derive("123");
      }, /Path must start with "m" or "M"/);
    });
  });

  describe("- after wipePrivateData()", function () {
    it("should not have private data", function () {
      const hdkey = HDKey.fromMasterSeed(
        hexToU8(fixtures.valid[6].seed),
      ).wipePrivateData();
      assert.equal(hdkey.getPrivateKey(), null);
      assert.equal(hdkey.getPrivateExtendedKey(), null);
      assert.throws(
        () => hdkey.sign(new Uint8Array(32)),
        "shouldn't be able to sign",
      );
      const childKey = hdkey.derive("m/0");
      assert.equal(childKey.getPublicExtendedKey(), fixtures.valid[7].public);
      assert.equal(childKey.getPrivateKey(), null);
      assert.equal(childKey.getPrivateExtendedKey(), null);
    });

    it("should have correct data", function () {
      // m/0/2147483647'/1/2147483646'/2
      const key =
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
      const hdkey = HDKey.fromExtendedKey(key).wipePrivateData();
      assert.equal(hdkey.versions.private, 0x0488ade4);
      assert.equal(hdkey.versions.public, 0x0488b21e);
      assert.equal(hdkey.depth, 5);
      assert.equal(hdkey.parentFingerprint, 0x31a507b8);
      assert.equal(hdkey.index, 2);
      assert.equal(
        u8ToHex(hdkey.chainCode),
        "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
      );
      assert.equal(
        u8ToHex(hdkey.publicKey),
        "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
      );
      assert.equal(
        u8ToHex(hdkey.identifier),
        "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220",
      );
    });

    it("should be able to verify signatures", function () {
      const fullKey = HDKey.fromMasterSeed(fixtures.valid[0].seed);
      // using JSON methods to clone before mutating
      const wipedKey = HDKey.fromJSON(fullKey.toJSON()).wipePrivateData();

      const hash = new Uint8Array(Buffer.alloc(32, 8));
      assert.ok(wipedKey.verify(hash, fullKey.sign(hash)));
    });

    it("should not throw if called on hdkey without private data", function () {
      const hdkey = HDKey.fromExtendedKey(fixtures.valid[0].public);
      assert.doesNotThrow(() => hdkey.wipePrivateData());
      assert.equal(hdkey.getPublicExtendedKey(), fixtures.valid[0].public);
    });
  });

  describe("Deriving a child key does not mutate the internal state", function () {
    it("should not mutate it when deriving with a private key", function () {
      const hdkey = HDKey.fromExtendedKey(fixtures.valid[0].private);
      const path = "m/123";
      const privateKeyBefore = u8ToHex(hdkey.getPrivateKey());

      const child = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.getPrivateKey()), privateKeyBefore);

      const child2 = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.getPrivateKey()), privateKeyBefore);

      const child3 = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.getPrivateKey()), privateKeyBefore);

      assert.equal(
        child.getPrivateKey().toString("hex"),
        child2.getPrivateKey().toString("hex"),
      );
      assert.equal(
        child2.getPrivateKey().toString("hex"),
        child3.getPrivateKey().toString("hex"),
      );
    });

    it("should not mutate it when deriving without a private key", function () {
      const hdkey = HDKey.fromExtendedKey(fixtures.valid[0].private);
      const path = "m/123/123/123";
      hdkey.wipePrivateData();

      const publicKeyBefore = u8ToHex(hdkey.publicKey);

      const child = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.publicKey), publicKeyBefore);

      const child2 = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.publicKey), publicKeyBefore);

      const child3 = hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.publicKey), publicKeyBefore);

      assert.equal(
        child.publicKey.toString("hex"),
        child2.publicKey.toString("hex"),
      );
      assert.equal(
        child2.publicKey.toString("hex"),
        child3.publicKey.toString("hex"),
      );
    });
  });
});

/**
 * @param {String} hex
 * @returns {Uint8Array}
 */
function hexToU8(hex) {
  let bufLen = hex.length / 2;
  let u8 = new Uint8Array(bufLen);

  let i = 0;
  let index = 0;
  let lastIndex = hex.length - 2;
  for (;;) {
    if (i > lastIndex) {
      break;
    }

    let h = hex.substr(i, 2);
    let b = parseInt(h, 16);
    u8[index] = b;

    i += 2;
    index += 1;
  }

  return u8;
}

/**
 * @param {Uint8Array} u8
 * @returns {String} hex
 */
function u8ToHex(u8) {
  /** @type {Array<String>} */
  let hex = [];

  u8.forEach(function (b) {
    let h = b.toString(16).padStart(2, "0");
    hex.push(h);
  });

  return hex.join("");
}
