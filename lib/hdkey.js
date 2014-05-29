var sha512 = require('sha512')

var MASTER_SECRET = new Buffer('Bitcoin seed')
var HARDENED_BASE = 0x80000000

//Bitcoin hardcoded by default, can use package `coininfo` for others
var VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function HDKey(seed) {
  if (seed == null || !Buffer.isBuffer(seed)) throw new Error('Must pass a seed that is a buffer.')
  if (!versions)
    versions = VERSIONS

  var I = sha512.hmac(MASTER_SECRET).finalize(seed)
  var IL = I.slice(0, 32)
  var IR = I.slice(32)


}

HDKey.prototype.derive = function(path) {
  
}

HDKey.prototype.deriveChild = function(index) {
   
}