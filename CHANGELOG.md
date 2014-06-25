0.2.0 / 2014-06-25
------------------
- upgraded `"ecurve": "^0.8.0"` to `"ecurve": "^1.0.0"`

0.1.0 / 2014-06-16
------------------
- removed semicolons per http://cryptocoinjs.com/about/contributing/#semicolons
- removed `ECKey` dep
- added `ecurve` dep
- removed `terst` dev dep for `assert`
- added method `fromMasterSeed(seedBuffer, [versions])`
- changed constructor from `new HDKey(masterSeed, [versions])` to `new HDKey([versions])`
- added properties: `privateKey` and `publicKey`
- removed method `getIdentifier()`, added property `identifier`
- removed method `getFingerprint()`, added property `fingerprint`
- renamed `private` to `privateExtendedKey`
- renamed `public` to `publicExtendedKey`
- added method `fromExtendedKey()`

0.0.1 / 2014-05-29
------------------
- initial release