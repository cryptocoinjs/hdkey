

//Bitcoin hardcoded by default, can use package `coininfo` for others
var VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function HDKey(seed, versions) {
  if (seed == null) throw new Error('Must pass a seed.')
  if (!versions)
    versions = VERSIONS

  
}