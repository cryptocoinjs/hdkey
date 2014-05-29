var crypto = require('crypto')
var bs58 = require('bs58')
var HDKey = require('../')
var fixtures = require('./fixtures')

require('terst')

function encode(buf) {
  var hash = crypto.createHash('sha256').update(buf).digest()
  var chksum = crypto.createHash('sha256').update(hash).digest().slice(0,4)
  return bs58.encode(Buffer.concat([buf, chksum]))
}

describe('hdkey', function() {
  var f = fixtures.valid[0]//.forEach(function(f) {
    it('should properly derive the chain path: ' + f.path, function() {
    
      var hdkey = new HDKey(new Buffer(f.seed, 'hex'))
      var childkey = hdkey.derive(f.path)

      EQ (encode(childkey.private), f.private)
      //EQ (encode(childkey.public), f.public)
    })    
  //})  
})