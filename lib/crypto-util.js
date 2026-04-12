/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {ALGORITHM, NIST_SECURITY_LEVEL_2} from './constants.js';

// Maps NIST security level to noble implementation and algorithm name
export const NIST_LEVEL_MAP = new Map([
  [2, {impl: ml_dsa44, name: ALGORITHM.MLDSA44}],
]);

export class CryptoKey {
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

// Signs data using ML-DSA.
export async function mldsaSign(key, data) {
  assertMldsaKey(key, 'private', 'sign');
  const {impl} = getImpl(key.algorithm.nistSecurityLevel);
  const msg = toUint8Array(data);
  const sig = impl.sign(msg, key._keyBytes);
  return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
}

// Verifies a signature over data using ML-DSA.
export async function mldsaVerify(key, signature, data) {
  assertMldsaKey(key, 'public', 'verify');
  const {impl} = getImpl(key.algorithm.nistSecurityLevel);
  const msg = toUint8Array(data);
  const sig = toUint8Array(signature);
  try {
    return impl.verify(sig, msg, key._keyBytes);
  } catch(e) {
    return false;
  }
}

// Generates a new ML-DSA key pair from a 32-byte seed.
export function mldsaGenerateKey(algorithm, extractable, keyUsages, seed) {
  const nistSecurityLevel = resolveNistSecurityLevel(algorithm);
  const {impl} = getImpl(nistSecurityLevel);
  const keyAlgorithm = {
    name: NIST_LEVEL_MAP.get(nistSecurityLevel).name,
    nistSecurityLevel
  };

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

// Imports an ML-DSA key from various formats.
export function mldsaImportKey(format, keyData, algorithm, extractable,
  keyUsages) {
  const nistSecurityLevel = resolveNistSecurityLevel(algorithm);
  const {impl} = getImpl(nistSecurityLevel);
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
      _keyBytes: toUint8Array(keyData),
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
    const seedBytes = toUint8Array(keyData);
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
    return importJwk({keyData, keyAlgorithm, nistSecurityLevel, impl,
      extractable, keyUsages});
  }

  throw new DOMException(`Unsupported key format "${format}".`,
    'NotSupportedError');
}

// Exports an ML-DSA CryptoKey to the given format.
export function mldsaExportKey(format, key) {
  if(!key.extractable) {
    throw new DOMException('Key is not extractable.', 'InvalidAccessError');
  }
  const {nistSecurityLevel} = key.algorithm;
  const {name} = getImpl(nistSecurityLevel);

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

// Resolves nistSecurityLevel from an algorithm object or integer.
export function resolveNistSecurityLevel(algorithm) {
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

// Returns the noble implementation and name for a given NIST security level.
export function getImpl(nistSecurityLevel) {
  const entry = NIST_LEVEL_MAP.get(nistSecurityLevel);
  if(!entry) {
    throw new DOMException(
      `Unsupported NIST security level "${nistSecurityLevel}". ` +
      'Only ML-DSA-44 (level 2) is supported.',
      'NotSupportedError');
  }
  return entry;
}

// Asserts key is a CryptoKey of the expected type with the expected usage.
export function assertMldsaKey(key, expectedType, expectedUsage) {
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

// Converts any BufferSource to Uint8Array without copying when possible.
export function toUint8Array(data) {
  if(data instanceof Uint8Array) {
    return data;
  }
  if(ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

// Imports a JWK-formatted key per webcryptomldsa spec Section 7.4.4.
function importJwk({
  keyData, keyAlgorithm, nistSecurityLevel, impl, extractable, keyUsages}) {
  const {name} = getImpl(nistSecurityLevel);
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
