var assert = require('assert')
var crypto = require('crypto')
var BigInteger = require('bigi')
var bs58 = require('bs58')
var ecurve = require('ecurve')
var secureRandom = require('secure-random')
var ecparams = ecurve.getCurveByName('secp256k1')

var HDKey = require('../')
var fixtures = require('./fixtures/hdkey')

function encode(buf) {
  var hash = crypto.createHash('sha256').update(buf).digest()
  var chksum = crypto.createHash('sha256').update(hash).digest().slice(0,4)
  return bs58.encode(Buffer.concat([buf, chksum]))
}

describe('hdkey', function() {
  describe('+ fromMasterSeed', function() {
    var f = fixtures.valid.forEach(function(f) {
      it('should properly derive the chain path: ' + f.path, function() {
      
        var hdkey = HDKey.fromMasterSeed(new Buffer(f.seed, 'hex'))
        var childkey = hdkey.derive(f.path)

        assert.equal(encode(childkey.privateExtendedKey), f.private)
        assert.equal(encode(childkey.publicExtendedKey), f.public)
      })    
    }) 
  })

  describe('- privateKey', function() {
    it('should throw an error if incorrect key size', function() {
      var hdkey = new HDKey()
      assert.throws(function() {
        hdkey.privateKey = new Buffer([1,2,3,4])  
      },/key must be 32/)           
    })
  })

  describe('- publicKey', function() {
    it('should throw an error if incorrect key size', function() {
      assert.throws(function() {
        var hdkey = new HDKey()
        hdkey.publicKey = new Buffer([1,2,3,4])
      },/key must be 33 or 65/)
    })

    it('should not throw if key is 33 bytes (compressed)', function() {
      var priv = secureRandom.randomBuffer(32)
      var pub = ecparams.params.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(true)
      assert.equal(pub.length, 33)
      var hdkey = new HDKey()
      hdkey.publicKey = pub
    })

    it('should not throw if key is 65 bytes (not compressed)', function() {
      var priv = secureRandom.randomBuffer(32)
      var pub = ecparams.params.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(false)
      assert.equal(pub.length, 65)
      var hdkey = new HDKey()
      hdkey.publicKey = pub
    })
  })

  describe('+ fromExtendedKey()', function() {
    describe('> when private', function() {
      it('should parse it', function() {
        //m/0/2147483647'/1/2147483646'/2
        var key = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        var keyBuffer = bs58.decode(key).slice(0, 78)
        var hdkey = HDKey.fromExtendedKey(keyBuffer)
        assert.equal(hdkey.versions.private, 0x0488ade4)
        assert.equal(hdkey.versions.public, 0x0488b21e)
        assert.equal(hdkey.depth, 5)
        assert.equal(hdkey.parentFingerprint, 0x31a507b8)
        assert.equal(hdkey.index, 2)
        assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
        assert.equal(hdkey.privateKey.toString('hex'), 'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23')
        assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
        assert.equal(hdkey.identifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
      })
    })

    describe('> when public', function() {
      it('should parse it', function() {
        //m/0/2147483647'/1/2147483646'/2
        var key = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        var keyBuffer = bs58.decode(key).slice(0, 78)
        var hdkey = HDKey.fromExtendedKey(keyBuffer)
        assert.equal(hdkey.versions.private, 0x0488ade4)
        assert.equal(hdkey.versions.public, 0x0488b21e)
        assert.equal(hdkey.depth, 5)
        assert.equal(hdkey.parentFingerprint, 0x31a507b8)
        assert.equal(hdkey.index, 2)
        assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
        assert.equal(hdkey.privateKey, null)
        assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
        assert.equal(hdkey.identifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
      })
    })
  })
})
