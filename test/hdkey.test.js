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
})
