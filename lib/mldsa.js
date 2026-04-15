/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import * as base64url from 'base64url-universal';
import {ml_dsa44, ml_dsa65, ml_dsa87} from '@noble/post-quantum/ml-dsa.js';
import {ALGORITHM} from './constants.js';

// Maps algorithm name to noble implementation
const ALGORITHM_MAP = new Map([
  [ALGORITHM.MLDSA44, {impl: ml_dsa44}],
  [ALGORITHM.MLDSA65, {impl: ml_dsa65}],
  [ALGORITHM.MLDSA87, {impl: ml_dsa87}],
]);

// Generates a new ML-DSA key pair from a random 32-byte seed.
export function generateKey({algorithm} = {}) {
  const {impl} = _getImpl(algorithm);
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const {publicKey: pubBytes, secretKey: secBytes} = impl.keygen(seed);
  return {
    publicKey: {
      type: 'public',
      algorithm,
      usages: ['verify'],
      _keyBytes: pubBytes,
    },
    secretKey: {
      type: 'private',
      algorithm,
      usages: ['sign'],
      _keyBytes: secBytes,
      _seedBytes: seed,
    }
  };
}

// Signs data using ML-DSA.
export function sign({secretKey, data} = {}) {
  _assertKey(secretKey, 'private', 'sign');
  const {impl} = _getImpl(secretKey.algorithm);
  const msg = _toUint8Array(data);
  const sig = impl.sign(msg, secretKey._keyBytes);
  return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
}

// Verifies a signature over data using ML-DSA.
export function verify({publicKey, signature, data} = {}) {
  _assertKey(publicKey, 'public', 'verify');
  const {impl} = _getImpl(publicKey.algorithm);
  const msg = _toUint8Array(data);
  const sig = _toUint8Array(signature);
  try {
    return impl.verify(sig, msg, publicKey._keyBytes);
  } catch(e) {
    return false;
  }
}

// Imports raw key bytes as a key object.
export function importKey({format, keyData, algorithm} = {}) {
  const {impl} = _getImpl(algorithm);

  if(format === 'raw-public') {
    return {
      type: 'public',
      algorithm,
      usages: ['verify'],
      _keyBytes: _toUint8Array(keyData),
    };
  }

  if(format === 'raw-seed') {
    const seedBytes = _toUint8Array(keyData);
    const {secretKey: secBytes} = impl.keygen(seedBytes);
    return {
      type: 'private',
      algorithm,
      usages: ['sign'],
      _keyBytes: secBytes,
      _seedBytes: seedBytes,
    };
  }

  if(format === 'jwk') {
    return _importJwk({jwk: keyData, algorithm, impl});
  }

  throw new TypeError(`Unsupported key format "${format}".`);
}

// Exports a key to JWK format.
export function exportKeyAsJwk({key} = {}) {
  const jwk = {
    kty: 'AKP',
    alg: key.algorithm,
    key_ops: key.usages,
    ext: true,
  };
  if(key.type === 'public') {
    jwk.pub = base64url.encode(key._keyBytes);
  } else {
    jwk.priv = base64url.encode(key._seedBytes);
  }
  return jwk;
}

function _getImpl(algorithm) {
  const entry = ALGORITHM_MAP.get(algorithm);
  if(!entry) {
    throw new TypeError(`Unsupported algorithm "${algorithm}".`);
  }
  return entry;
}

function _assertKey(key, expectedType, expectedUsage) {
  if(!key || typeof key !== 'object') {
    throw new TypeError('Invalid key.');
  }
  if(key.type !== expectedType) {
    throw new TypeError(`Expected a ${expectedType} key.`);
  }
  if(!key.usages.includes(expectedUsage)) {
    throw new TypeError(`Key does not have "${expectedUsage}" usage.`);
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

// Imports a JWK-formatted key per webcryptomldsa spec Section 7.4.4.
function _importJwk({jwk, algorithm, impl}) {
  if(jwk.kty !== 'AKP') {
    throw new TypeError(`JWK "kty" must be "AKP", got "${jwk.kty}".`);
  }
  if(jwk.alg && jwk.alg !== algorithm) {
    throw new TypeError(`JWK "alg" must be "${algorithm}", got "${jwk.alg}".`);
  }

  if(jwk.priv !== undefined) {
    const seedBytes = base64url.decode(jwk.priv);
    const {publicKey: derivedPub, secretKey: secBytes} = impl.keygen(seedBytes);
    if(jwk.pub) {
      const suppliedPub = base64url.decode(jwk.pub);
      if(suppliedPub.length !== derivedPub.length ||
        !suppliedPub.every((b, i) => b === derivedPub[i])) {
        throw new TypeError(
          'JWK "pub" does not match public key derived from "priv".');
      }
    }
    return {
      type: 'private',
      algorithm,
      usages: ['sign'],
      _keyBytes: secBytes,
      _seedBytes: seedBytes,
    };
  }

  if(!jwk.pub) {
    throw new TypeError('JWK missing "pub" field.');
  }
  return {
    type: 'public',
    algorithm,
    usages: ['verify'],
    _keyBytes: base64url.decode(jwk.pub),
  };
}
