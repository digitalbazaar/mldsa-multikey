/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {randomBytes} from 'node:crypto';
import {ALGORITHM, NIST_SECURITY_LEVEL_2} from './constants.js';

// Maps NIST security level (nistSecurityLevel value) to noble implementation
// and WebCrypto algorithm name string
const NIST_LEVEL_MAP = new Map([
  [2, {impl: ml_dsa44, name: ALGORITHM.MLDSA44}],
]);

class CryptoKey {
  constructor({type, extractable, algorithm, usages, _keyBytes, _seedBytes}) {
    this._type = type;
    this._extractable = extractable;
    this._algorithm = algorithm;
    this._usages = usages;
    // Raw key material kept private
    // For public keys: the raw public key bytes
    // For private keys: the raw expanded secret key bytes
    this._keyBytes = _keyBytes;
    // For private keys: the 32-byte seed used for JWK / pkcs8 export
    this._seedBytes = _seedBytes ?? null;
  }

  // type: "public" | "private" | "secret"
  get type() {
    return this._type;
  }

  // extractable: boolean
  get extractable() {
    return this._extractable;
  }

  // algorithm: KeyAlgorithm object (e.g. {name: "MLDSA", nistSecurityLevel: 2})
  get algorithm() {
    return this._algorithm;
  }

  // usages: Array of "sign" | "verify"
  get usages() {
    return this._usages;
  }
}

class SubtleCrypto {
  /* eslint-disable no-unused-vars */
  async encrypt(algorithm, key, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async decrypt(algorithm, key, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  // Signs data using ML-DSA-44.
  // algorithm: {name: 'MLDSA', hash: {name: string}} or 'MLDSA'
  // key: CryptoKey with type "private" and usage "sign"
  // data: BufferSource
  // Returns: Promise<ArrayBuffer>
  async sign(algorithm, key, data) {
    _assertMldsaKey(key, 'private', 'sign');
    const {impl} = _getImpl(key.algorithm.nistSecurityLevel);
    const msg = _toUint8Array(data);
    const sig = impl.sign(msg, key._keyBytes);
    return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
  }

  // Verifies a signature over data using ML-DSA-44.
  // algorithm: {name: 'MLDSA', hash: {name: string}} or 'MLDSA'
  // key: CryptoKey with type "public" and usage "verify"
  // signature: BufferSource
  // data: BufferSource
  // Returns: Promise<boolean>
  async verify(algorithm, key, signature, data) {
    _assertMldsaKey(key, 'public', 'verify');
    const {impl} = _getImpl(key.algorithm.nistSecurityLevel);
    const msg = _toUint8Array(data);
    const sig = _toUint8Array(signature);
    try {
      return impl.verify(sig, msg, key._keyBytes);
    } catch(e) {
      return false;
    }
  }

  /* eslint-disable no-unused-vars */
  async digest(algorithm, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  // Generates a new ML-DSAkey pair.
  // algorithm: {name: 'MLDSA', nistSecurityLevel: 2}
  // extractable: boolean
  // keyUsages: ['sign', 'verify']
  // Returns: Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>
  async generateKey(algorithm, extractable, keyUsages) {
    const nistSecurityLevel = _resolveNistSecurityLevel(algorithm);
    const {impl} = _getImpl(nistSecurityLevel);
    const keyAlgorithm = {
      name: NIST_LEVEL_MAP.get(nistSecurityLevel).name,
      nistSecurityLevel
    };

    // Generate seed and derive key pair; store seed for later export
    const seed = new Uint8Array(randomBytes(32));
    const {publicKey: pubBytes, secretKey: secBytes} = impl.keygen(seed);

    const publicKey = new CryptoKey({
      type: 'public',
      extractable: true,
      algorithm: keyAlgorithm,
      usages: keyUsages.filter(u => u === 'verify'),
      _keyBytes: pubBytes,
    });

    const privateKey = new CryptoKey({
      type: 'private',
      extractable,
      algorithm: keyAlgorithm,
      usages: keyUsages.filter(u => u === 'sign'),
      _keyBytes: secBytes,
      _seedBytes: seed,
    });

    return {publicKey, privateKey};
  }

  /* eslint-disable no-unused-vars */
  async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable,
    keyUsages) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async deriveBits(algorithm, baseKey, length) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  // Imports a key from spki, pkcs8, raw, or jwk format.
  // format: "spki" | "pkcs8" | "jwk" | "raw-public" | "raw-seed"
  // keyData: BufferSource or JsonWebKey
  // algorithm: {name: 'MLDSA', nistSecurityLevel: 2}
  // extractable: boolean
  // keyUsages: ['sign'] or ['verify']
  // Returns: Promise<CryptoKey>
  async importKey(format, keyData, algorithm, extractable, keyUsages) {
    const nistSecurityLevel = _resolveNistSecurityLevel(algorithm);
    const {impl} = _getImpl(nistSecurityLevel);
    const keyAlgorithm = {
      name: NIST_LEVEL_MAP.get(nistSecurityLevel).name,
      nistSecurityLevel
    };

    if(format === 'spki' || format === 'pkcs8') {
      throw new DOMException(
        `"${format}" import is not supported for ML-DSA keys.`,
        'NotSupportedError');
    }

    if(format === 'raw-public') {
      const pubBytes = _toUint8Array(keyData);
      return new CryptoKey({
        type: 'public',
        extractable,
        algorithm: keyAlgorithm,
        usages: keyUsages.filter(u => u === 'verify'),
        _keyBytes: pubBytes,
      });
    }

    if(format === 'raw-secret') {
      const secBytes = keyData;
      return new CryptoKey({
        type: 'private',
        extractable,
        algorithm: keyAlgorithm,
        usages: keyUsages.filter(u => u === 'sign'),
        _keyBytes: secBytes
      });
    }

    if(format === 'raw-seed') {
      const seedBytes = _toUint8Array(keyData);
      if(seedBytes.length !== 32) {
        throw new DOMException(
          'Raw seed must be exactly 32 bytes.', 'DataError');
      }
      const {secretKey: secBytes} = impl.keygen(seedBytes);
      return new CryptoKey({
        type: 'private',
        extractable,
        algorithm: keyAlgorithm,
        usages: keyUsages.filter(u => u === 'sign'),
        _keyBytes: secBytes,
        _seedBytes: seedBytes,
      });
    }

    if(format === 'jwk') {
      return _importJwk({keyData, keyAlgorithm, nistSecurityLevel, impl,
        extractable, keyUsages});
    }

    throw new DOMException(`Unsupported key format "${format}".`,
      'NotSupportedError');
  }

  // Exports a CryptoKey to the given format.
  // format: "spki" | "pkcs8" | "jwk" | "raw-public" | "raw-seed"
  // key: CryptoKey (must be extractable)
  // Returns: Promise<ArrayBuffer | JsonWebKey>
  async exportKey(format, key) {
    if(!key.extractable) {
      throw new DOMException('Key is not extractable.', 'InvalidAccessError');
    }
    const {nistSecurityLevel} = key.algorithm;
    const {name} = _getImpl(nistSecurityLevel);

    if(format === 'spki' || format === 'pkcs8') {
      throw new DOMException(
        `"${format}" export is not supported for ML-DSA keys.`,
        'NotSupportedError');
    }

    if(format === 'raw-public') {
      if(key.type !== 'public') {
        throw new DOMException(
          '"raw-public" format requires a public key.', 'InvalidAccessError');
      }
      return key._keyBytes.buffer.slice(
        key._keyBytes.byteOffset,
        key._keyBytes.byteOffset + key._keyBytes.length);
    }

    if(format === 'raw-secret') {
      if(key.type !== 'private') {
        throw new DOMException(
          '"raw-secret" format requires a private key.', 'InvalidAccessError');
      }
      return key._keyBytes.buffer.slice(
        key._keyBytes.byteOffset,
        key._keyBytes.byteOffset + key._keyBytes.length);
    }

    if(format === 'raw-seed') {
      if(key.type !== 'private') {
        throw new DOMException(
          '"raw-seed" format requires a private key.', 'InvalidAccessError');
      }
      if(!key._seedBytes) {
        throw new DOMException(
          'Private key has no exportable seed.', 'InvalidAccessError');
      }
      return key._seedBytes.buffer.slice(
        key._seedBytes.byteOffset,
        key._seedBytes.byteOffset + key._seedBytes.length);
    }

    if(format === 'jwk') {
      // JWK format: kty "AKP", alg "ML-DSA-44", pub (base64url public key),
      // priv (base64url seed, private keys only)
      // Per webcryptomldsa spec Section 7.4.5
      const jwk = {
        kty: 'AKP',
        alg: name,
        pub: base64url.encode(key._keyBytes),
        key_ops: key.usages,
        ext: key.extractable,
      };
      if(key.type === 'private') {
        if(!key._keyBytes) {
          throw new DOMException(
            'Private key has no exportable seed.', 'InvalidAccessError');
        }
        jwk.priv = base64url.encode(key._keyBytes);
      }
      return jwk;
    }

    throw new DOMException(`Unsupported key format "${format}".`,
      'NotSupportedError');
  }

  /* eslint-disable no-unused-vars */
  async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
    unwrappedKeyAlgorithm, extractable, keyUsages) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */
}

// Crypto matches the Web Crypto API Crypto interface:
// https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto
class Crypto {
  constructor() {
    // subtle: SubtleCrypto — the SubtleCrypto interface for low-level
    // cryptographic operations
    this.subtle = new SubtleCrypto();
  }

  // Fills the given TypedArray with cryptographically strong random values.
  // typedArray: Int8Array | Uint8Array | ... (max 65536 bytes)
  // Returns: the same typedArray, filled in place
  getRandomValues(typedArray) {
    const bytes = randomBytes(typedArray.byteLength);
    typedArray.set(new typedArray.constructor(
      bytes.buffer, bytes.byteOffset, typedArray.length));
    return typedArray;
  }

  // Returns a randomly generated UUID v4 string.
  randomUUID() {
    const bytes = randomBytes(16);
    // Set version 4 bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant bits
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-` +
      `${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
}

// --- Helpers ---

// Resolves nistSecurityLevel (NIST security level integer) from an algorithm
// object or integer. Accepts {name, nistSecurityLevel} or a bare integer.
function _resolveNistSecurityLevel(algorithm) {
  if(algorithm?.nistSecurityLevel) {
    return algorithm.nistSecurityLevel;
  }
  if(algorithm.name === ALGORITHM.MLDSA44) {
    return NIST_SECURITY_LEVEL_2;
  }

  throw new DOMException(
    `Unknown NIST security level for given algorithm "${algorithm}". ` +
    'Only ML-DSA-44 (level 2) is supported.',
    'NotSupportedError');
}

// Returns the noble implementation and name for a given NIST security level
function _getImpl(nistSecurityLevel) {
  const entry = NIST_LEVEL_MAP.get(nistSecurityLevel);
  if(!entry) {
    throw new DOMException(
      `Unsupported NIST security level "${nistSecurityLevel}". ` +
      'Only ML-DSA-44 (level 2) is supported.',
      'NotSupportedError');
  }
  return entry;
}

// Asserts key is a CryptoKey of the expected type with the expected usage
function _assertMldsaKey(key, expectedType, expectedUsage) {
  if(!(key instanceof CryptoKey)) {
    throw new DOMException('Invalid key.', 'InvalidAccessError');
  }
  if(key.type !== expectedType) {
    throw new DOMException(
      `Expected a ${expectedType} key.`, 'InvalidAccessError');
  }
  if(!key.usages.includes(expectedUsage)) {
    throw new DOMException(
      `Key does not have "${expectedUsage}" usage.`, 'InvalidAccessError');
  }
}

// Converts any BufferSource to Uint8Array without copying when possible
function _toUint8Array(data) {
  if(data instanceof Uint8Array) {
    return data;
  }
  if(ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

// Imports a JWK-formatted key per webcryptomldsa spec Section 7.4.4
function _importJwk({
  keyData, keyAlgorithm, nistSecurityLevel, impl, extractable, keyUsages}) {
  const {name} = _getImpl(nistSecurityLevel);
  const jwk = keyData;

  if(jwk.kty !== 'AKP') {
    throw new DOMException(
      `JWK "kty" must be "AKP", got "${jwk.kty}".`, 'DataError');
  }
  if(jwk.alg && jwk.alg !== name) {
    throw new DOMException(
      `JWK "alg" must be "${name}", got "${jwk.alg}".`, 'DataError');
  }
  if(jwk.use && jwk.use !== 'sig') {
    throw new DOMException(
      `JWK "use" must be "sig", got "${jwk.use}".`, 'DataError');
  }
  if(jwk.ext === false && extractable) {
    throw new DOMException(
      'JWK "ext" is false but extractable is true.', 'DataError');
  }

  if(jwk.priv !== undefined) {
    // Private key: priv = base64url seed, pub = base64url public key
    const seedBytes = base64url.decode(jwk.priv);
    const {publicKey: derivedPub, secretKey: secBytes} = impl.keygen(seedBytes);
    // Verify that the pub field matches the derived public key
    if(jwk.pub) {
      const suppliedPub = base64url.decode(jwk.pub);
      if(suppliedPub.length !== derivedPub.length ||
        !suppliedPub.every((b, i) => b === derivedPub[i])) {
        throw new DOMException(
          'JWK "pub" does not match public key derived from "priv".',
          'DataError');
      }
    }
    return new CryptoKey({
      type: 'private',
      extractable,
      algorithm: keyAlgorithm,
      usages: keyUsages.filter(u => u === 'sign'),
      _keyBytes: secBytes,
      _seedBytes: seedBytes,
    });
  }

  // Public key: pub = base64url public key bytes
  if(!jwk.pub) {
    throw new DOMException('JWK missing "pub" field.', 'DataError');
  }
  const pubBytes = base64url.decode(jwk.pub);
  return new CryptoKey({
    type: 'public',
    extractable,
    algorithm: keyAlgorithm,
    usages: keyUsages.filter(u => u === 'verify'),
    _keyBytes: pubBytes,
  });
}

export const webcrypto = new Crypto();
export {CryptoKey};
