import {
  createCipheriv,
  createDecipheriv,
  DecipherGCM,
  randomBytes
} from 'crypto'
import {
  crypto_pwhash,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_MEMLIMIT_MODERATE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  ready as libsodiumReady
} from 'libsodium-wrappers'
import { promisify } from 'util'

/**
 * Which Authenticated Encryption mode to use?
 *
 * Matthew Green recommends GCM for most applications:
 * https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/
 *
 * Very fast, patent-free, supported by OpenSSL/Node, not vulnerable to padding
 * oracle attacks (using other modes necessitates MACs to secure against those).
 */
const ENCRYPTION_ALGORITHM = 'aes-256-gcm'

/**
 * NIST recommends 96-bit IVs for AES-GCM; alternative lengths can introduce weaknesses:
 * https://crypto.stackexchange.com/questions/26790/how-bad-it-is-using-the-same-iv-twice-with-aes-gcm
 */
const INITIALIZATION_VECTOR_LENGTH_BYTES = 12

const KEY_LENGTH_BYTES = 32
const SALT_LENGTH_BYTES = 16

/** Due to WASM limitations, constants are undefined until Libsodium is loaded */
const defaultKeyDerivationConfig = () => ({
  /**
   * Defaults to Argon2Id v1.3, considered state-of-the-art due to it's strong
   * ASIC resistance compared to PBKDF2, bcrypt, and scrypt:
   * https://security.stackexchange.com/questions/193351/in-2018-what-is-the-recommended-hash-to-store-passwords-bcrypt-scrypt-argon2
   */
  KEY_DERIVATION_ALGORITHM: crypto_pwhash_ALG_DEFAULT,

  /**
   * Libsodium provides sensible defaults for web (INTERACTIVE) and
   * elevated security (MEDIUM, SENSITIVE) to configure the iteration
   * count and memory hardness of the key derivation function.
   *
   * - On MacBook Pro 2016, OPSLIMIT_INTERACTIVE takes 600ms vs
   *   3.7s for OPSLIMIT_MEDIUM
   * - MEMLIMIT_INTERACTIVE requires 64MiB of dedicated RAM, whereas
   *   MEMLIMIT_MEDIUM requires 256MiB of dedicated RAM
   * - More info: https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function
   */
  KEY_DERIVATION_MEMLIMIT: crypto_pwhash_MEMLIMIT_MODERATE,
  KEY_DERIVATION_OPSLIMIT: crypto_pwhash_OPSLIMIT_INTERACTIVE
})

export const generateEncryptionKey = async (
  password: string
): Promise<(plaintext: string) => Promise<EncryptedConfig>> => {
  await libsodiumReady

  const salt = await promisify(randomBytes)(SALT_LENGTH_BYTES)

  const defaultConfig = defaultKeyDerivationConfig()
  const encryptionKey = crypto_pwhash(
    KEY_LENGTH_BYTES,
    password,
    salt,
    defaultConfig.KEY_DERIVATION_OPSLIMIT,
    defaultConfig.KEY_DERIVATION_MEMLIMIT,
    defaultConfig.KEY_DERIVATION_ALGORITHM
  )

  return async (plaintext: string) => {
    /**
     * Generate a new IV for each message encrypted with the same key:
     * - https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce
     * - https://crypto.stackexchange.com/questions/26790/how-bad-it-is-using-the-same-iv-twice-with-aes-gcm
     */
    const iv = await promisify(randomBytes)(INITIALIZATION_VECTOR_LENGTH_BYTES)

    const cipher = createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv)

    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext)),
      cipher.final()
    ])

    return {
      ciphertext: ciphertext.toString('base64'),
      encryptionConfig: {
        algorithm: ENCRYPTION_ALGORITHM,
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64')
      },
      keyDerivationConfig: {
        algorithm: defaultConfig.KEY_DERIVATION_ALGORITHM,
        length: KEY_LENGTH_BYTES,
        salt: salt.toString('base64'),
        opsLimit: defaultConfig.KEY_DERIVATION_OPSLIMIT,
        memLimit: defaultConfig.KEY_DERIVATION_MEMLIMIT
      }
    }
  }
}

export const decrypt = async (
  password: string,
  { ciphertext, keyDerivationConfig, encryptionConfig }: EncryptedConfig
): Promise<string> => {
  await libsodiumReady

  const encryptionKey = crypto_pwhash(
    KEY_LENGTH_BYTES,
    password,
    Buffer.from(keyDerivationConfig.salt, 'base64'),
    keyDerivationConfig.opsLimit,
    keyDerivationConfig.memLimit,
    keyDerivationConfig.algorithm
  )
  const decipher = createDecipheriv(
    encryptionConfig.algorithm,
    encryptionKey,
    Buffer.from(encryptionConfig.iv, 'base64')
  ) as DecipherGCM

  decipher.setAuthTag(Buffer.from(encryptionConfig.authTag, 'base64'))

  return decipher.update(ciphertext, 'base64', 'utf8') + decipher.final('utf8')
}

interface EncryptedConfig {
  /** Encrypted text, base64 encoded */
  readonly ciphertext: string

  readonly encryptionConfig: {
    /** OpenSSL identifier for the symmetric key encryption algorithm */
    readonly algorithm: string

    /** Initialization vector, base64 encoded */
    readonly iv: string

    /** Authentication tag, used to ensure data integrity during decryption, base64 encoded */
    readonly authTag: string
  }

  readonly keyDerivationConfig: {
    /** Libsodium identifier for the hashing algorithm and version used (defaults to Argon2Id) */
    readonly algorithm: number

    /** Length in bytes of the derived encryption key/hash */
    readonly length: number

    /** Salt for Libsodium, base64 encoded */
    readonly salt: string

    /** OPSLIMIT parameter for Libsodium, denoting the number of CPU cycles to perform */
    readonly opsLimit: number

    /** MEMLIMIT parameter for Libsodium, denoting the max amount of RAM the function will utilize */
    readonly memLimit: number
  }
}
