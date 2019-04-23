# symmetric-encrypt

[![NPM Package](https://img.shields.io/npm/v/symmetric-encrypt.svg?style=flat-square&logo=npm)](https://npmjs.org/package/symmetric-encrypt)
[![CircleCI](https://img.shields.io/circleci/project/github/kincaidoneil/symmetric-encrypt/master.svg?style=flat-square&logo=circleci)](https://circleci.com/gh/kincaidoneil/symmetric-encrypt/master)
[![Codecov](https://img.shields.io/codecov/c/github/kincaidoneil/symmetric-encrypt/master.svg?style=flat-square&logo=codecov)](https://codecov.io/gh/kincaidoneil/symmetric-encrypt)
[![Known Vulnerabilities](https://snyk.io/test/github/kincaidoneil/symmetric-encrypt/badge.svg?targetFile=package.json&style=flat-square)](https://snyk.io/test/github/kincaidoneil/symmetric-encrypt?targetFile=package.json)
[![Prettier](https://img.shields.io/badge/code_style-prettier-brightgreen.svg?style=flat-square)](https://prettier.io/)
[![MIT License](https://img.shields.io/github/license/kincaidoneil/symmetric-encrypt.svg?style=flat-square)](https://github.com/kincaidoneil/symmetric-encrypt/blob/master/LICENSE)

> Password-based encryption and decryption in Node.js

- AES-GCM for fast and secure symmetric encryption
- Argon2Id for high work-factor and ASIC-resistant key derivation, using Libsodium compiled to WASM
- Portable function parameters for encryption and key derivation, encoded in the output for backwards compatibility
- Best practices such as salting, regenerating IVs for each new message, and using auth tags to enforce integrity
- Simple API, designed to use with a separate persistence layer

### Install

```bash
npm install symmetric-encrypt
```

Requires Node.js 10+.

### Usage

```js
const { generateEncryptionKey, decrypt } = require('symmetric-encrypt')

async function run() {
  /**
   * The key only needs to be generated once per session, so
   * `encrypt` can be called multiple times with different messages
   */
  const encrypt = await generateEncryptionKey('some password')
  const encryptedConfig = await encrypt('this is the message')

  /**
   * For instance, `encryptedConfig` could be encoded
   * in JSON and written to a file. Later, the file could
   * be opened and parsed as JSON, to be decrypted.
   */

  const message = await decrypt('some password', encryptedConfig)
  console.log(message) // -> "this is the message"
}

run().catch(err => console.error(err))
```
