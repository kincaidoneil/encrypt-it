import test from 'ava'
import { decrypt, generateEncryptionKey } from '..'
import { performance } from 'perf_hooks'

test('decrypts an encrypted message', async t => {
  const password = 'foo bar bleh'
  const message = 'This is some text!'

  const encrypt = await generateEncryptionKey(password)
  const encryptedMessage = await encrypt(message)
  const decryptedMessage = await decrypt(password, encryptedMessage)

  t.is(message, decryptedMessage)
})

test('throws if password is wrong', async t => {
  const password = 'p@ssw0rd'
  const incorrectPassword = 'password'
  const message = 'The quick brown fox jumped over the lazy dog.'

  const encrypt = await generateEncryptionKey(password)
  const encryptedMessage = await encrypt(message)
  await t.throwsAsync(decrypt(incorrectPassword, encryptedMessage))
})

test('unique encryption key generated for same password', async t => {
  const password = 'lorem ipsum'
  const message = 'The quick brown fox jumped over the lazy dog.'

  const encrypt = await generateEncryptionKey(password)
  const encrypt2 = await generateEncryptionKey(password)

  const encryptedMessage = await encrypt(message)
  const encryptedMessage2 = await encrypt2(message)

  t.not(encryptedMessage.ciphertext, encryptedMessage2.ciphertext)
  t.not(
    encryptedMessage.keyDerivationConfig.salt,
    encryptedMessage2.keyDerivationConfig.salt
  )
  t.not(
    encryptedMessage.encryptionConfig.iv,
    encryptedMessage2.encryptionConfig.iv
  )
})

test('generates a unique iv for each message with same key', async t => {
  const password = '1234567890'
  const message = 'The quick brown fox jumped over the lazy dog.'
  const message2 = 'lorem ipsum dolor sit amet'

  const encrypt = await generateEncryptionKey(password)
  const encryptedMessage = await encrypt(message)
  const encryptedMessage2 = await encrypt(message2)

  t.not(
    encryptedMessage.encryptionConfig.iv,
    encryptedMessage2.encryptionConfig.iv
  )
})

test.serial('encryption key takes at least 200ms to generate', async t => {
  const password = '1234567890'

  const start = performance.now()
  await generateEncryptionKey(password)
  const time = performance.now() - start

  t.true(time > 200)
})
