/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {
  EXTRACTABLE,
  MULTIBASE_BASE64URL_HEADER,
  MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER,
  MULTIKEY_CONTEXT_V1_URL,
  NIST_SECURITY_LEVEL_2
} from './constants.js';
import {webcrypto} from './crypto.js';
import {
  getNistSecurityLevelFromPublicMultikey,
  getNistSecurityLevelFromSecretMultikey,
  setPublicKeyHeader,
  setSecretKeyHeader
} from './helpers.js';

// imports raw key bytes as CryptoKey instances
export async function cryptoKeyfromRaw({
  nistSecurityLevel, secretKey, publicKey
} = {}) {
  const algorithm = {name: 'MLDSA', nistSecurityLevel};

  let cryptoKey;
  if(secretKey) {
    cryptoKey = await webcrypto.subtle.importKey(
      'raw-secret', secretKey, algorithm, EXTRACTABLE, ['sign']);
  } else {
    cryptoKey = await webcrypto.subtle.importKey(
      'raw-public', publicKey, algorithm, EXTRACTABLE, ['verify']);
  }
  return cryptoKey;
}

// exports key pair
export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  exported.id = keyPair.id;
  exported.type = 'Multikey';
  exported.controller = keyPair.controller;

  if(publicKey) {
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    exported.publicKeyMultibase = toPublicKeyMultibase({jwk});
  }

  if(secretKey && keyPair.secretKey) {
    const {nistSecurityLevel} = keyPair.secretKey.algorithm;
    const secretKeyBytes = new Uint8Array(
      await webcrypto.subtle.exportKey('raw-secret', keyPair.secretKey));
    // leave room for multicodec header (2 bytes)
    const multikey = new Uint8Array(2 + secretKeyBytes.length);
    setSecretKeyHeader({nistSecurityLevel, buffer: multikey});
    multikey.set(secretKeyBytes, 2);
    exported.secretKeyMultibase =
      MULTIBASE_BASE64URL_HEADER + base64url.encode(multikey);
  }

  return exported;
}

// imports key pair
export async function importKeyPair({
  id, controller, secretKeyMultibase, publicKeyMultibase
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const keyPair = {id, controller};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === MULTIBASE_BASE64URL_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base64url-encoded string.');
  }
  const publicMultikey = base64url.decode(publicKeyMultibase.slice(1));

  // check multikey header for a known ML-DSA-44 value
  if(!(publicMultikey[0] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[1])) {
    throw new TypeError('Unsupported public key multikey header.');
  }
  // strip 2-byte multicodec header to get raw public key bytes
  const rawPublicKey = publicMultikey.subarray(2);

  const nistSecurityLevel =
    getNistSecurityLevelFromPublicMultikey({publicMultikey});
  const algorithm = {name: 'MLDSA', nistSecurityLevel};

  // import public key via raw-public format
  keyPair.publicKey = await webcrypto.subtle.importKey(
    'raw-public', rawPublicKey, algorithm, EXTRACTABLE, ['verify']);

  // import secret key via raw-secret format
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
      secretKeyMultibase[0] === MULTIBASE_BASE64URL_HEADER)) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base64url-encoded string.');
    }
    const secretMultikey = base64url.decode(secretKeyMultibase.slice(1));

    // ensure secret key multikey header appropriately matches the
    // public key multikey header
    _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey});

    // omit multikey header (2 bytes) to get raw expanded secret key bytes
    const secretKeyBytes = secretMultikey.subarray(2);
    keyPair.secretKey = await webcrypto.subtle.importKey(
      'raw-secret', secretKeyBytes, algorithm, EXTRACTABLE, ['sign']);
  }

  return keyPair;
}

export function toPublicKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'AKP') {
    throw new TypeError('"jwk.kty" must be "AKP".');
  }
  return base64url.decode(jwk.pub);
}

export function toPublicKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'AKP') {
    throw new TypeError('"jwk.kty" must be "AKP".');
  }
  const nistSecurityLevel = _nistSecurityLevelFromAlg(jwk.alg);
  const publicKey = base64url.decode(jwk.pub);
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKey.length);
  setPublicKeyHeader({nistSecurityLevel, buffer: multikey});
  multikey.set(publicKey, 2);
  return MULTIBASE_BASE64URL_HEADER + base64url.encode(multikey);
}

export function toSecretKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'AKP') {
    throw new TypeError('"jwk.kty" must be "AKP".');
  }
  // priv is the secret key
  return base64url.decode(jwk.priv);
}

export function toSecretKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'AKP') {
    throw new TypeError('"jwk.kty" must be "AKP".');
  }
  const nistSecurityLevel = _nistSecurityLevelFromAlg(jwk.alg);
  const secretKey = base64url.decode(jwk.priv);
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKey.length);
  setSecretKeyHeader({nistSecurityLevel, buffer: multikey});
  multikey.set(secretKey, 2);
  return MULTIBASE_BASE64URL_HEADER + base64url.encode(multikey);
}

// ensures that public key header matches secret key header
function _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey}) {
  const publicKeyNistSecurityLevel =
    getNistSecurityLevelFromPublicMultikey({publicMultikey});
  const secretKeyNistSecurityLevel =
    getNistSecurityLevelFromSecretMultikey({secretMultikey});
  if(publicKeyNistSecurityLevel !== secretKeyNistSecurityLevel) {
    throw new Error(
      `Public key NIST security level ('${publicKeyNistSecurityLevel}') ` +
      `does not match secret key NIST security level ` +
      `('${secretKeyNistSecurityLevel}').`);
  }
}

// maps JWK alg string to NIST security level integer
function _nistSecurityLevelFromAlg(alg) {
  if(alg === 'ML-DSA-44') {
    return NIST_SECURITY_LEVEL_2;
  }
  throw new TypeError(`Unsupported JWK alg "${alg}".`);
}
