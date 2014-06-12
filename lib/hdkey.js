var sha512 = require('sha512')
var ECKey = require('eckey')
var BigInteger = require('bigi')
var crypto = require('crypto')
var assert = require('assert')

module.exports = HDKey

var MASTER_SECRET = new Buffer('Bitcoin seed')
var HARDENED_OFFSET = 0x80000000
var LEN = 78

//I hate that this is hardcoded, but for now...
var N = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

//Bitcoin hardcoded by default, can use package `coininfo` for others
var VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function HDKey(seed) {
  //if (seed == null || !Buffer.isBuffer(seed)) throw new Error('Must pass a seed that is a buffer.')
  if (seed == null) return //this is for deriveChild()

  var I = sha512.hmac(MASTER_SECRET).finalize(seed)
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  this.priv = new ECKey(IL, true)
  this.pub = this.priv.publicPoint
  this.chaincode = IR
  this.depth = 0
  this.index = 0
}

Object.defineProperty(HDKey.prototype, 'private', {
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
    this.chaincode.copy(buffer, 13)

    // 33 bytes: the public key or private key data
    assert(this.priv, 'Missing private key')

    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.priv.privateKey.copy(buffer, 46)


    return buffer
  }
})

Object.defineProperty(HDKey.prototype, 'public', {
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
    this.chaincode.copy(buffer, 13)

    // X9.62 encoding for public keys
    var buf = new Buffer(this.pub.getEncoded(true))
    buf.copy(buffer, 45)
    
    return buffer
  }
})

HDKey.prototype.getIdentifier = function() {
  //just computing pubKeyHash here
  var buf = new Buffer(this.pub.getEncoded(true))
  var sha = crypto.createHash('sha256').update(buf).digest()
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
    assert(this.priv, 'Could not derive hardened child key')

    var pk = this.priv.privateKey
    var zb = new Buffer([0])
    pk = Buffer.concat([zb, pk])

    // data = 0x00 || ser256(kpar) || ser32(index)
    data = Buffer.concat([pk, indexBuffer])

  // Normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    data = Buffer.concat([
      new Buffer(this.pub.getEncoded(true)),
      indexBuffer
    ])
  }

  //var I = crypto.HmacSHA512(data, this.chaincode)
  var I = sha512.hmac(this.chaincode).finalize(data)
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var hd = new HDKey()
  var pIL = BigInteger.fromBuffer(IL)

  // Private parent key -> private child key
  if (this.priv) {
    // ki = parse256(IL) + kpar (mod n)
    var ki = pIL.add(BigInteger.fromBuffer(this.priv.privateKey)).mod(N)

    // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
    if (pIL.compareTo(N) >= 0 || ki.signum() === 0) {
      return this.derive(index + 1)
    }

    hd.priv = new ECKey(ki.toBuffer(), true)
    hd.pub = hd.priv.publicPoint

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

  hd.chaincode = IR
  hd.depth = this.depth + 1
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)
  hd.index = index

  return hd
}