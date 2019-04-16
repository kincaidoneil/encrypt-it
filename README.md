# symmetric-encrypt

> Password-based encryption and decryption in Node.js

- AES-GCM for fast and secure symmetric encryption
- Argon2Id for high work-factor and ASIC-resistant key derivation, using a Libsodium WASM implementation
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
