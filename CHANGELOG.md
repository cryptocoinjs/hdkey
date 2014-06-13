x.y.z / 2014-06-dd
------------------
- removed semicolons per http://cryptocoinjs.com/about/contributing/#semicolons
- removed `ECKey` dep
- added `ecurve` dep
- removed `terst` dev dep for `assert`
- added method `fromMasterSeed(seedBuffer, [versions])`
- changed constructor from `new HDKey(masterSeed, [versions])` to `new HDKey([versions])`
- added properties: `privateKey` and `publicKey`

0.0.1 / 2014-05-29
------------------
- initial release