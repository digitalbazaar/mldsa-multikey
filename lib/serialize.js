/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as base64url from 'base64url-universal';
import {
  EXTRACTABLE,
  MULTIBASE_BASE58_HEADER,
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

// ML-DSA-44 PKCS#8 PrivateKeyInfo prefix (before the 32-byte seed):
//   SEQUENCE { INTEGER 0, AlgorithmIdentifier { OID 2.16.840.1.101.3.4.3.17 },
//     OCTET STRING { [0] IMPLICIT { seed } } }
const PKCS8_PREFIXES = new Map([
  [NIST_SECURITY_LEVEL_2, {
    secret: new Uint8Array([
      48, 52, 2, 1, 0, 48, 11, 6,
      9, 96, 134, 72, 1, 101, 3, 4,
      3, 17, 4, 34, 128, 32
    ])
  }]
]);

// ML-DSA-44 SubjectPublicKeyInfo prefix (before the 1312-byte public key):
//   SEQUENCE { AlgorithmIdentifier { OID 2.16.840.1.101.3.4.3.17 },
//     BIT STRING { 0x00 || pubKey } }
const SPKI_PREFIXES = new Map([
  [NIST_SECURITY_LEVEL_2, new Uint8Array([
    48, 130, 5, 50, 48, 11, 6,
    9, 96, 134, 72, 1, 101, 3,
    4, 3, 17, 3, 130, 5, 33, 0
  ])]
]);

// imports raw key bytes as CryptoKey instances
export async function cryptoKeyfromRaw({
  nistSecurityLevel, secretKey, publicKey
} = {}) {
  const algorithm = {name: 'MLDSA', nistSecurityLevel};

  let cryptoKey;
  if(secretKey) {
    cryptoKey = await webcrypto.subtle.importKey(
      'raw-seed', secretKey, algorithm, EXTRACTABLE, ['sign']);
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
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.secretKey);
    exported.secretKeyMultibase = toSecretKeyMultibase({jwk});
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
    publicKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));

  const nistSecurityLevel =
    getNistSecurityLevelFromPublicMultikey({publicMultikey});
  const algorithm = {name: 'MLDSA', nistSecurityLevel};

  // import public key via spki format
  const spki = _multikeyToSpki({publicMultikey});
  keyPair.publicKey = await webcrypto.subtle.importKey(
    'spki', spki, algorithm, EXTRACTABLE, ['verify']);

  // import secret key if given
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
      secretKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.');
    }
    const secretMultikey = base58.decode(secretKeyMultibase.slice(1));

    // ensure secret key multikey header appropriately matches the
    // public key multikey header
    _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey});

    // convert to pkcs8 format for import
    const pkcs8 = _multikeyToPkcs8({secretMultikey});
    keyPair.secretKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, ['sign']);
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
  return MULTIBASE_BASE58_HEADER + base58.encode(multikey);
}

export function toSecretKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'AKP') {
    throw new TypeError('"jwk.kty" must be "AKP".');
  }
  // priv is the 32-byte seed
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
  return MULTIBASE_BASE58_HEADER + base58.encode(multikey);
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

// converts multikey secret key to PKCS#8 format (seed-only)
function _multikeyToPkcs8({secretMultikey}) {
  const nistSecurityLevel =
    getNistSecurityLevelFromSecretMultikey({secretMultikey});
  // omit multikey header (2 bytes) to get raw seed bytes
  const seedKey = secretMultikey.subarray(2);
  return _rawToPkcs8({nistSecurityLevel, seedKey});
}

function _multikeyToSpki({publicMultikey}) {
  const nistSecurityLevel =
    getNistSecurityLevelFromPublicMultikey({publicMultikey});
  // omit multikey header (2 bytes) to get raw public key bytes
  const publicKey = publicMultikey.subarray(2);
  return _rawToSpki({nistSecurityLevel, publicKey});
}

// converts seed bytes to PKCS#8 format (seed-only, ML-DSA-44 style)
export function _rawToPkcs8({nistSecurityLevel, seedKey}) {
  const headers = PKCS8_PREFIXES.get(nistSecurityLevel);
  if(!headers) {
    throw new Error(`Unsupported NIST security level "${nistSecurityLevel}".`);
  }
  const pkcs8 = new Uint8Array(headers.secret.length + seedKey.length);
  pkcs8.set(headers.secret, 0);
  pkcs8.set(seedKey, headers.secret.length);
  return pkcs8;
}

// converts public key bytes to SubjectPublicKeyInfo format
function _rawToSpki({nistSecurityLevel, publicKey}) {
  const header = SPKI_PREFIXES.get(nistSecurityLevel);
  if(!header) {
    throw new Error(`Unsupported NIST security level "${nistSecurityLevel}".`);
  }
  const spki = new Uint8Array(header.length + publicKey.length);
  spki.set(header, 0);
  spki.set(publicKey, header.length);
  return spki;
}

// maps JWK alg string to NIST security level integer
function _nistSecurityLevelFromAlg(alg) {
  if(alg === 'ML-DSA-44') {
    return NIST_SECURITY_LEVEL_2;
  }
  throw new TypeError(`Unsupported JWK alg "${alg}".`);
}
