/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {ALGORITHM, NIST_SECURITY_LEVEL_2} from './constants.js';

// Maps NIST security level to noble implementation and algorithm name
const NIST_LEVEL_MAP = new Map([
  [2, {impl: ml_dsa44, name: ALGORITHM.MLDSA44}],
]);

export class CryptoKey {
  constructor({type, extractable, algorithm, usages, _keyBytes, _seedBytes}) {
    this._type = type;
    this._extractable = extractable;
    this._algorithm = algorithm;
    this._usages = usages;
    this._keyBytes = _keyBytes;
    this._seedBytes = _seedBytes ?? null;
  }

  get type() {
    return this._type;
  }

  get extractable() {
    return this._extractable;
  }

  get algorithm() {
    return this._algorithm;
  }

  get usages() {
    return this._usages;
  }
}

// Extends the browser's native crypto with ML-DSA support. Non-ML-DSA
// operations are delegated to the native window.crypto / self.crypto.
class MldsaSubtleCrypto {
  constructor(nativeSubtle) {
    this._native = nativeSubtle;
  }

  // Proxy all standard methods to native subtle crypto
  async encrypt(algorithm, key, data) {
    return this._native.encrypt(algorithm, key, data);
  }

  async decrypt(algorithm, key, data) {
    return this._native.decrypt(algorithm, key, data);
  }

  async digest(algorithm, data) {
    return this._native.digest(algorithm, data);
  }

  async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable,
    keyUsages) {
    return this._native.deriveKey(
      algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages);
  }

  async deriveBits(algorithm, baseKey, length) {
    return this._native.deriveBits(algorithm, baseKey, length);
  }

  async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
    return this._native.wrapKey(format, key, wrappingKey, wrapAlgorithm);
  }

  async unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
    unwrappedKeyAlgorithm, extractable, keyUsages) {
    return this._native.unwrapKey(
      format, wrappedKey, unwrappingKey, unwrapAlgorithm,
      unwrappedKeyAlgorithm, extractable, keyUsages);
  }

  // Route sign/verify/generateKey/importKey/exportKey to ML-DSA when the
  // algorithm is ML-DSA, otherwise delegate to native subtle crypto.
  async sign(algorithm, key, data) {
    if(_isMldsaKey(key)) {
      _assertMldsaKey(key, 'private', 'sign');
      const {impl} = _getImpl(key.algorithm.nistSecurityLevel);
      const msg = _toUint8Array(data);
      const sig = impl.sign(msg, key._keyBytes);
      return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
    }
    return this._native.sign(algorithm, key, data);
  }

  async verify(algorithm, key, signature, data) {
    if(_isMldsaKey(key)) {
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
    return this._native.verify(algorithm, key, signature, data);
  }

  async generateKey(algorithm, extractable, keyUsages) {
    if(_isMldsaAlgorithm(algorithm)) {
      const nistSecurityLevel = _resolveNistSecurityLevel(algorithm);
      const {impl} = _getImpl(nistSecurityLevel);
      const keyAlgorithm = {
        name: NIST_LEVEL_MAP.get(nistSecurityLevel).name,
        nistSecurityLevel
      };

      const seed = new Uint8Array(32);
      (self.crypto ?? window.crypto).getRandomValues(seed);
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
    return this._native.generateKey(algorithm, extractable, keyUsages);
  }

  async importKey(format, keyData, algorithm, extractable, keyUsages) {
    if(_isMldsaAlgorithm(algorithm)) {
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
        return new CryptoKey({
          type: 'public',
          extractable,
          algorithm: keyAlgorithm,
          usages: keyUsages.filter(u => u === 'verify'),
          _keyBytes: _toUint8Array(keyData),
        });
      }

      if(format === 'raw-secret') {
        return new CryptoKey({
          type: 'private',
          extractable,
          algorithm: keyAlgorithm,
          usages: keyUsages.filter(u => u === 'sign'),
          _keyBytes: keyData,
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
    return this._native.importKey(format, keyData, algorithm, extractable,
      keyUsages);
  }

  async exportKey(format, key) {
    if(_isMldsaKey(key)) {
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
            '"raw-secret" format requires a private key.',
            'InvalidAccessError');
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
    return this._native.exportKey(format, key);
  }
}

// Extended crypto object that wraps the browser's native crypto
class BrowserCrypto {
  constructor(nativeCrypto) {
    this._native = nativeCrypto;
    this.subtle = new MldsaSubtleCrypto(nativeCrypto.subtle);
  }

  getRandomValues(typedArray) {
    return this._native.getRandomValues(typedArray);
  }

  randomUUID() {
    return this._native.randomUUID();
  }
}

// --- Helpers ---

function _isMldsaAlgorithm(algorithm) {
  if(!algorithm) {
    return false;
  }
  const name = typeof algorithm === 'string' ? algorithm : algorithm.name;
  return name === ALGORITHM.MLDSA44 ||
    (algorithm?.nistSecurityLevel !== undefined);
}

function _isMldsaKey(key) {
  return key instanceof CryptoKey;
}

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

function _toUint8Array(data) {
  if(data instanceof Uint8Array) {
    return data;
  }
  if(ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

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
    const seedBytes = base64url.decode(jwk.priv);
    const {publicKey: derivedPub, secretKey: secBytes} = impl.keygen(seedBytes);
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

const _nativeCrypto = self.crypto ?? window.crypto;
export const webcrypto = new BrowserCrypto(_nativeCrypto);
