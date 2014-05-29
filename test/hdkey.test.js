var HDKey = require('../')
var fixtures = require('./fixtures')

require('terst')

function encode(buf) {
  
}

describe('hdkey', function() {
  it('should properly derive the chain path', function() {
    fixtures.valid.forEach(function(f) {
      var hdkey = new HDKey(new Buffer(f.seed, 'hex'))
      var childkey = hdkey.derive(f.path)

      EQ (encode(childkey.private), f.private)
      EQ (encode(childkey.public), f.public)
    })    
  })  
})