"use strict";

var assert = require("assert");
var BigInteger = require("bigi");
var crypto = require("crypto");
var ecurve = require("ecurve");
var curve = ecurve.getCurveByName("secp256k1");
var HDKey = require("../");
var fixtures = require("./fixtures/hdkey");

var Secp256k1 = require("@dashincubator/secp256k1");

// trinity: mocha
/* global describe it */

describe("hdkey", function () {
  describe("+ fromMasterSeed", function () {
    for (let f of fixtures.valid) {
      it("should properly derive the chain path: " + f.path, async function () {
        var hdkey = await HDKey.fromMasterSeed(hexToU8(f.seed));
        var childkey = await hdkey.derive(f.path);
        let xpriv = await childkey.getPrivateExtendedKey();

        assert.equal(xpriv, f.private);
        assert.equal(await childkey.getPublicExtendedKey(), f.public);
      });

      describe(
        "> " + f.path + " get<Private|Public>ExtendedKey() / fromExtendedKey()",
        function () {
          it("should return an object read for JSON serialization", async function () {
            var hdkey = await HDKey.fromMasterSeed(hexToU8(f.seed));
            var childkey = await hdkey.derive(f.path);

            var obj = {
              xpriv: f.private,
              xpub: f.public,
            };

            var childObj = {
              xpriv: await childkey.getPrivateExtendedKey(),
              xpub: await childkey.getPublicExtendedKey(),
            };
            assert.deepEqual(childObj, obj);

            var newKey = await HDKey.fromExtendedKey(childObj.xpriv);
            assert.strictEqual(await newKey.getPrivateExtendedKey(), f.private);
            assert.strictEqual(await newKey.getPublicExtendedKey(), f.public);
          });
        },
      );
    }
  });

  describe("- privateKey", function () {
    it("should throw an error if incorrect key size", async function () {
      var hdkey = HDKey.create();
      assert.rejects(async function () {
        await hdkey.setPrivateKey(Uint8Array.from([1, 2, 3, 4]));
      }, /key must be 32/);
    });
  });

  describe("- publicKey", function () {
    it("should throw an error if incorrect key size", async function () {
      assert.rejects(async function () {
        var hdkey = HDKey.create();
        await hdkey.setPublicKey(Uint8Array.from([1, 2, 3, 4]));
      }, /key must be 33 or 65/);
    });

    it("should not throw if key is 33 bytes (compressed)", async function () {
      var rnd = crypto.randomBytes(32);
      var priv = new Uint8Array(rnd);

      var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(true);
      assert.equal(pub.length, 33);
      var hdkey = HDKey.create();
      await hdkey.setPublicKey(new Uint8Array(pub));
    });

    it("should not throw if key is 65 bytes (not compressed)", async function () {
      var rnd = crypto.randomBytes(32);
      var priv = new Uint8Array(rnd);

      var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(false);
      assert.equal(pub.length, 65);
      var hdkey = HDKey.create();
      await hdkey.setPublicKey(new Uint8Array(pub));
    });
  });

  describe("+ fromExtendedKey()", function () {
    describe("> when private", function () {
      it("should parse it", async function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
        var hdkey = await HDKey.fromExtendedKey(key);
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
      it("should parse it", async function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
        var hdkey = await HDKey.fromExtendedKey(key);
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

      it("should parse it without verification", async function () {
        // m/0/2147483647'/1/2147483646'/2
        var key =
          "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
        var hdkey = await HDKey.fromExtendedKey(key, null, false);
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
    it("should work", async function () {
      var key =
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
      var hdkey = await HDKey.fromExtendedKey(key);

      var ma = new Uint8Array(32);
      var mb = new Uint8Array(Buffer.alloc(32, 8));
      var a = await sign(hdkey, ma);
      var b = await sign(hdkey, mb);
      assert.equal(
        u8ToHex(a),
        "6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06",
      );
      assert.equal(
        u8ToHex(b),
        "dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381",
      );
      assert.equal(await verify(hdkey, ma, a), true);
      assert.equal(await verify(hdkey, mb, b), true);
      assert.equal(
        await verify(hdkey, new Uint8Array(32), new Uint8Array(64)),
        false,
      );
      assert.equal(await verify(hdkey, ma, b), false);
      assert.equal(await verify(hdkey, mb, a), false);

      assert.rejects(async function () {
        await verify(hdkey, new Uint8Array(99), a);
      }, /message.*length/);
      assert.rejects(async function () {
        await verify(hdkey, ma, new Uint8Array(99));
      }, /signature.*length/);
    });
  });

  describe("> when deriving public key", function () {
    it("should work", async function () {
      var key =
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
      var hdkey = await HDKey.fromExtendedKey(key);

      var path = "m/3353535/2223/0/99424/4/33";
      var derivedHDKey = await hdkey.derive(path);

      var expected =
        "xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1";
      assert.equal(await derivedHDKey.getPublicExtendedKey(), expected);
    });
  });

  describe("> when private key integer is less than 32 bytes", function () {
    it("should work", async function () {
      var seed = "000102030405060708090a0b0c0d0e0f";
      var masterKey = await HDKey.fromMasterSeed(hexToU8(seed));

      var newKey = await masterKey.derive("m/44'/6'/4'");
      var expected =
        "xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx";
      assert.equal(await newKey.getPrivateExtendedKey(), expected);
    });
  });

  describe("HARDENED_OFFSET", function () {
    it("should be set", async function () {
      assert(HDKey.HARDENED_OFFSET);
    });
  });

  describe("> when private key has leading zeros", function () {
    it("will include leading zeros when hashing to derive child", async function () {
      var key =
        "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr";
      var hdkey = await HDKey.fromExtendedKey(key);
      assert.equal(
        u8ToHex(hdkey.getPrivateKey()),
        "00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd",
      );
      var derived = await hdkey.derive("m/44'/0'/0'/0/0'");
      assert.equal(
        u8ToHex(derived.getPrivateKey()),
        "3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb",
      );
    });
  });

  describe("> when private key is null", function () {
    it("privateExtendedKey should return null and not throw", async function () {
      var seed = "000102030405060708090a0b0c0d0e0f";
      var masterKey = await HDKey.fromMasterSeed(hexToU8(seed));

      assert.ok(await masterKey.getPrivateExtendedKey(), "xpriv is truthy");
      masterKey.wipePrivateData();

      assert.doesNotThrow(async function () {
        await masterKey.getPrivateExtendedKey();
      });

      assert.ok(!(await masterKey.getPrivateExtendedKey()), "xpriv is falsy");
    });
  });

  describe(" - when the path given to derive contains only the master extended key", function () {
    it("should return the same hdkey instance", async function () {
      const hdKeyInstance = await HDKey.fromMasterSeed(
        hexToU8(fixtures.valid[0].seed),
      );
      assert.equal(await hdKeyInstance.derive("m"), hdKeyInstance);
      assert.equal(await hdKeyInstance.derive("M"), hdKeyInstance);
      assert.equal(await hdKeyInstance.derive("m'"), hdKeyInstance);
      assert.equal(await hdKeyInstance.derive("M'"), hdKeyInstance);
    });
  });

  describe(" - when the path given to derive does not begin with master extended key", function () {
    it("should throw an error", async function () {
      assert.rejects(async function () {
        const hdkey = HDKey.create();
        await hdkey.derive("123");
      }, /Path must start with "m" or "M"/);
    });
  });

  describe("- after wipePrivateData()", function () {
    it("should not have private data", async function () {
      const hdkey = (
        await HDKey.fromMasterSeed(hexToU8(fixtures.valid[6].seed))
      ).wipePrivateData();
      assert.equal(hdkey.getPrivateKey(), null);
      assert.equal(await hdkey.getPrivateExtendedKey(), null);
      assert.rejects(async function () {
        await sign(hdkey, new Uint8Array(32));
      }, "shouldn't be able to sign");
      const childKey = await hdkey.derive("m/0");
      assert.equal(
        await childKey.getPublicExtendedKey(),
        fixtures.valid[7].public,
      );
      assert.equal(childKey.getPrivateKey(), null);
      assert.equal(await childKey.getPrivateExtendedKey(), null);
    });

    it("should have correct data", async function () {
      // m/0/2147483647'/1/2147483646'/2
      const key =
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
      const hdkey = (await HDKey.fromExtendedKey(key)).wipePrivateData();
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

    it("should be able to verify signatures", async function () {
      const fullKey = await HDKey.fromMasterSeed(
        hexToU8(fixtures.valid[0].seed),
      );
      // using get/from methods to clone before mutating
      const wipedKey = await HDKey.fromExtendedKey(
        await fullKey.getPrivateExtendedKey(),
      );
      wipedKey.wipePrivateData();

      const hash = new Uint8Array(Buffer.alloc(32, 8));
      const sig = await sign(fullKey, hash);
      assert.ok(await verify(wipedKey, hash, sig));
    });

    it("should not throw if called on hdkey without private data", async function () {
      const hdkey = await HDKey.fromExtendedKey(fixtures.valid[0].public);
      assert.doesNotThrow(() => hdkey.wipePrivateData());
      assert.equal(
        await hdkey.getPublicExtendedKey(),
        fixtures.valid[0].public,
      );
    });
  });

  describe("Deriving a child key does not mutate the internal state", function () {
    it("should not mutate it when deriving with a private key", async function () {
      const hdkey = await HDKey.fromExtendedKey(fixtures.valid[0].private);
      const path = "m/123";
      const privateKeyBefore = u8ToHex(hdkey.getPrivateKey());

      const child = await hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.getPrivateKey()), privateKeyBefore);

      const child2 = await hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.getPrivateKey()), privateKeyBefore);

      const child3 = await hdkey.derive(path);
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

    it("should not mutate it when deriving without a private key", async function () {
      const hdkey = await HDKey.fromExtendedKey(fixtures.valid[0].private);
      const path = "m/123/123/123";
      hdkey.wipePrivateData();

      const publicKeyBefore = u8ToHex(hdkey.publicKey);

      const child = await hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.publicKey), publicKeyBefore);

      const child2 = await hdkey.derive(path);
      assert.equal(u8ToHex(hdkey.publicKey), publicKeyBefore);

      const child3 = await hdkey.derive(path);
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

async function sign(hdkey, hash) {
  let _privateKey = hdkey.getPrivateKey();
  if (!_privateKey) {
    throw new Error("Private Key must be set");
  }

  // Note: `extraEntropy: null` for testing
  // (normally we'd want this to be `true`, or `crypto.getRandomValues(32)`)
  let sigOpts = { canonical: true, extraEntropy: null };
  let der = await Secp256k1.sign(hash, _privateKey, sigOpts);
  let sig = new Uint8Array(64);

  let rSizeIndex = 3;
  let offset = rSizeIndex + 1;
  let rSize = der[rSizeIndex];
  if (0x21 === rSize) {
    offset += 1;
  }
  let r = der.subarray(offset, offset + 32);
  sig.set(r, 0);

  offset += 2 + 32;
  let sLen = der[offset - 1];
  if (0x21 === sLen) {
    offset += 1;
  }
  let s = der.subarray(offset, offset + 32);
  sig.set(s, 32);

  return sig;
}

async function verify(hdkey, hash, sig) {
  assert(hash.length === 32, "message length must be 32 bytes.");
  assert(sig.length === 64, "signature length must be 64 bytes.");
  let verifyOpts = { strict: true }; // require canonical

  let r = sig.subarray(0, 32);
  let s = sig.subarray(32, 64);

  let len = 2 + 2 + 32 + 2 + 32;
  if (sig[0] >= 0x80) {
    len += 1;
  }
  if (sig[32] >= 0x80) {
    len += 1;
  }

  let der = new Uint8Array(len);
  der[0] = 0x30;
  der[1] = 0x44;

  let offset = 1;
  der[offset] = 0x02;
  offset += 1;
  if (r[0] < 0x80) {
    der[offset] = 0x20;
  } else {
    der[offset] = 0x21;
    offset += 1;
    der[offset] = 0x00;
  }
  offset += 1;
  der.set(r, offset);
  offset += 32;

  der[offset] = 0x02;
  offset += 1;
  if (s[0] < 0x80) {
    der[offset] = 0x20;
  } else {
    der[offset] = 0x21;
    offset += 1;
    der[offset] = 0x00;
  }
  offset += 1;
  der.set(s, offset);

  return await Secp256k1.verify(sig, hash, hdkey.publicKey, verifyOpts);
}
