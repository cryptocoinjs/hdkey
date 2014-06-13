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
var VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function HDKey(versions) {
  this.versions = versions || VERSIONS
  this.depth = 0
  this.index = 0
  this._privateKey = null
  this._privateKeyInteger = BigInteger.ZERO
  this._publicKey = null
  this.chainCode = null
}

Object.defineProperty(HDKey.prototype, 'privateKey', {
  get: function() {
    return this._privateKey
  },
  set: function(value) {
    assert.equal(value.length, 32, 'Private key must be 32 bytes.')
    this._privateKey = value
    this._privateKeyInteger = BigInteger.fromBuffer(this._privateKey)
    this._publicKey = ecparams.params.G.multiply(this._privateKeyInteger).getEncoded(true) //force compressed point
  }
})

Object.defineProperty(HDKey.prototype, 'publicKey', {
  get: function() {
    return this._publicKey
  },
  set: function(value) {
    assert(value.length === 33 || value.length === 65, 'Public key must be 33 or 65 bytes.')
    var pt = Point.decodeFrom(ecparams.curve, value)
    this._publicKey = pt.getEncoded(true) //force compressed point
    this._privateKey = null
    this._privateKeyInteger = null
  }
})

Object.defineProperty(HDKey.prototype, 'privateOld', {
  get: function() {
    // Version
    var version = VERSIONS.private
    var buffer = new Buffer(LEN)

    // 4 bytes: version bytes
    buffer.writeUInt32BE(version, 0)

    // Depth
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.writeUInt8(this.depth, 4)

    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    var fingerprint = this.depth ? this.parentFingerprint : 0x00000000
    buffer.writeUInt32BE(fingerprint, 5)

    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in Big endian. (0x00000000 if master key)
    buffer.writeUInt32BE(this.index, 9)

    // 32 bytes: the chain code
    this.chainCode.copy(buffer, 13)

    // 33 bytes: the public key or private key data
    assert(this.privateKey, 'Missing private key')

    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.privateKey.copy(buffer, 46)


    return buffer
  }
})

Object.defineProperty(HDKey.prototype, 'publicOld', {
  get: function() {
    // Version
    var version = VERSIONS.public
    var buffer = new Buffer(LEN)

    // 4 bytes: version bytes
    buffer.writeUInt32BE(version, 0)

    // Depth
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.writeUInt8(this.depth, 4)

    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    var fingerprint = this.depth ? this.parentFingerprint : 0x00000000
    buffer.writeUInt32BE(fingerprint, 5)

    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in Big endian. (0x00000000 if master key)
    buffer.writeUInt32BE(this.index, 9)

    // 32 bytes: the chain code
    this.chainCode.copy(buffer, 13)

    // X9.62 encoding for public keys
    var buf = this.publicKey
    buf.copy(buffer, 45)
    
    return buffer
  }
})

HDKey.prototype.getIdentifier = function() {
  //just computing pubKeyHash here
  var sha = crypto.createHash('sha256').update(this.publicKey).digest()
  return crypto.createHash('rmd160').update(sha).digest()
}

HDKey.prototype.getFingerprint = function() {
  return this.getIdentifier().slice(0, 4)
}


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
    var childIndex = parseInt(usePrivate ? c.slice(0, c.length - 1) : c) & 0x7fffffff

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
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)
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

//temporary
function setPrivPub(hd, privKey) {
  hd.priv = privKey

}

