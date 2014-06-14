var assert = require('assert')
var crypto = require('crypto')
var BigInteger = require('bigi')
var ecurve = require('ecurve')
var ecparams = ecurve.getCurveByName('secp256k1')
var Point = ecurve.Point
var sha512 = require('sha512')

module.exports = HDKey

var MASTER_SECRET = new Buffer('Bitcoin seed')
var HARDENED_OFFSET = 0x80000000
var LEN = 78

var N = ecparams.params.n

//Bitcoin hardcoded by default, can use package `coininfo` for others
var BITCOIN_VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function HDKey(versions) {
  this.versions = versions || BITCOIN_VERSIONS
  this.depth = 0
  this.index = 0
  this._privateKey = null
  this._privateKeyInteger = BigInteger.ZERO
  this._publicKey = null
  this.chainCode = null
}

Object.defineProperty(HDKey.prototype, 'fingerprint', {get: function() { return this.identifier.slice(0, 4) } })
Object.defineProperty(HDKey.prototype, 'identifier', {get: function() { return this._identifier } })

Object.defineProperty(HDKey.prototype, 'privateKey', {
  get: function() {
    return this._privateKey
  },
  set: function(value) {
    assert.equal(value.length, 32, 'Private key must be 32 bytes.')
    this._privateKey = value
    this._privateKeyInteger = BigInteger.fromBuffer(this._privateKey)
    this._publicKey = ecparams.params.G.multiply(this._privateKeyInteger).getEncoded(true) //force compressed point
    this._identifier = hash160(this.publicKey)
  }
})

Object.defineProperty(HDKey.prototype, 'publicKey', {
  get: function() {
    return this._publicKey
  },
  set: function(value) {
    assert(value.length === 33 || value.length === 65, 'Public key must be 33 or 65 bytes.')
    var pt = Point.decodeFrom(ecparams, value)
    this._publicKey = pt.getEncoded(true) //force compressed point
    this._privateKey = null
    this._privateKeyInteger = null
  }
})

Object.defineProperty(HDKey.prototype, 'privateOld', {
  get: function() {
    return serialize(this, this.versions.private, Buffer.concat([new Buffer([0]), this.privateKey]))
  }
})

Object.defineProperty(HDKey.prototype, 'publicOld', {
  get: function() {
    return serialize(this, this.versions.public, this.publicKey)
  }
})


HDKey.prototype.derive = function(path) {
  var e = path.split('/')

  // Special cases:
  if (path == 'm' || path == 'M' || path == 'm\'' || path == 'M\'')
    return this

  var hkey = this
  for (var i in e) {
    var c = e[i]

    if (i == 0 ) {
      if (c != 'm') throw new Error('invalid path')
      continue
    }

    var usePrivate = (c.length > 1) && (c[c.length-1] == '\'')
    var childIndex = parseInt(usePrivate ? c.slice(0, c.length - 1) : c) & (HARDENED_OFFSET - 1)

    if (usePrivate)
      childIndex += HARDENED_OFFSET

    hkey = hkey.deriveChild(childIndex)
  }

  return hkey
}

HDKey.prototype.deriveChild = function(index) {
  var isHardened = index >= HARDENED_OFFSET
  var indexBuffer = new Buffer(4)
  indexBuffer.writeUInt32BE(index, 0)

  var data

  // Hardened child
  if (isHardened) {
    assert(this.privateKey, 'Could not derive hardened child key')

    var pk = this.privateKey
    var zb = new Buffer([0])
    pk = Buffer.concat([zb, pk])

    // data = 0x00 || ser256(kpar) || ser32(index)
    data = Buffer.concat([pk, indexBuffer])

  // Normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    data = Buffer.concat([
      this.publicKey,
      indexBuffer
    ])
  }

  //var I = crypto.HmacSHA512(data, this.chaincode)
  var I = sha512.hmac(this.chainCode).finalize(data)
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var hd = new HDKey(this.versions)
  var pIL = BigInteger.fromBuffer(IL)

  // Private parent key -> private child key
  if (this.privateKey) {
    // ki = parse256(IL) + kpar (mod n)
    var ki = pIL.add(BigInteger.fromBuffer(this.privateKey)).mod(N)

    // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
    if (pIL.compareTo(N) >= 0 || ki.signum() === 0) {
      return this.derive(index + 1)
    }

    //hd.priv = new ECKey(ki.toBuffer(), true)
    //hd.pub = hd.priv.publicPoint
    hd.privateKey = ki.toBuffer()

  // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    //var Ki = ecparams.getG().multiply(pIL).add(this.pub.Q)

    // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
    //if (pIL.compareTo(ecparams.getN()) >= 0 || Ki.isInfinity()) {
    //  return this.derive(index + 1)
    //}

    //hd.pub = new ECPubKey(Ki, true)
  }

  hd.chainCode = IR
  hd.depth = this.depth + 1
  hd.parentFingerprint = this.fingerprint.readUInt32BE(0)
  hd.index = index

  return hd
}

HDKey.fromMasterSeed = function(seedBuffer, versions) {
  var I = sha512.hmac(MASTER_SECRET).finalize(seedBuffer)
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var hdkey = new HDKey(versions)
  hdkey.chainCode = IR
  hdkey.privateKey = IL

  return hdkey
}

function serialize(hdkey, version, key) {
  // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33) 
  var buffer = new Buffer(LEN)
  
  buffer.writeUInt32BE(version, 0)
  buffer.writeUInt8(hdkey.depth, 4)
  
  var fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000
  buffer.writeUInt32BE(fingerprint, 5)
  buffer.writeUInt32BE(hdkey.index, 9)
  
  hdkey.chainCode.copy(buffer, 13)
  key.copy(buffer, 45)

  return buffer
}

function hash160(buf) {
  var sha = crypto.createHash('sha256').update(buf).digest()
  return crypto.createHash('rmd160').update(sha).digest()
}

