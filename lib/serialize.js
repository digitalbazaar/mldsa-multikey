/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import * as base64url from 'base64url-universal';
import {
  ALGORITHM,
  MULTIBASE_BASE64URL_HEADER,
  MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER,
  MULTICODEC_MLDSA65_PUBLIC_KEY_HEADER,
  MULTICODEC_MLDSA87_PUBLIC_KEY_HEADER,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {exportKeyAsJwk, importKey} from './mldsa.js';
import {
  getAlgorithmFromPublicMultikey,
  getAlgorithmFromSecretMultikey,
  setPublicKeyHeader,
  setSecretKeySeedHeader
} from './helpers.js';

// exports key pair
export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  const exported = {};
  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  exported.id = keyPair.id;
  exported.type = 'Multikey';
  exported.controller = keyPair.controller;

  if(publicKey) {
    const jwk = exportKeyAsJwk({key: keyPair.publicKey});
    exported.publicKeyMultibase = toPublicKeyMultibase({jwk});
  }

  if(secretKey && keyPair.secretKey) {
    exported.secretKeyMultibase =
      secretKeyToMultibase({key: keyPair.secretKey});
  }

  return exported;
}

// imports key pair
export function importKeyPair({
  id, controller, secretKeyMultibase, publicKeyMultibase
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const keyPair = {id, controller};

  // import public key
  if(!(typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === MULTIBASE_BASE64URL_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base64url-encoded string.');
  }
  const publicMultikey = base64url.decode(publicKeyMultibase.slice(1));

  // check multikey header for a known ML-DSA value
  const isKnownHeader =
    (publicMultikey[0] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[0] &&
      publicMultikey[1] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[1]) ||
    (publicMultikey[0] === MULTICODEC_MLDSA65_PUBLIC_KEY_HEADER[0] &&
      publicMultikey[1] === MULTICODEC_MLDSA65_PUBLIC_KEY_HEADER[1]) ||
    (publicMultikey[0] === MULTICODEC_MLDSA87_PUBLIC_KEY_HEADER[0] &&
      publicMultikey[1] === MULTICODEC_MLDSA87_PUBLIC_KEY_HEADER[1]);
  if(!isKnownHeader) {
    throw new TypeError('Unsupported public key multikey header.');
  }
  const rawPublicKey = publicMultikey.subarray(2);

  const algorithm = getAlgorithmFromPublicMultikey({publicMultikey});
  keyPair.publicKey = importKey({
    format: 'raw-public', keyData: rawPublicKey, algorithm});

  // import secret key (always seed format)
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
      secretKeyMultibase[0] === MULTIBASE_BASE64URL_HEADER)) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base64url-encoded string.');
    }
    const secretMultikey = base64url.decode(secretKeyMultibase.slice(1));

    _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey});

    // strip 2-byte header to get seed bytes, then expand
    keyPair.secretKey = importKey({
      format: 'raw-seed', keyData: secretMultikey.subarray(2), algorithm
    });
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
  const algorithm = _algorithmFromAlg(jwk.alg);
  const publicKey = base64url.decode(jwk.pub);
  const multikey = new Uint8Array(2 + publicKey.length);
  setPublicKeyHeader({algorithm, buffer: multikey});
  multikey.set(publicKey, 2);
  return MULTIBASE_BASE64URL_HEADER + base64url.encode(multikey);
}

// encodes a secret key as a multibase multikey string using the seed format
export function secretKeyToMultibase({key} = {}) {
  const {algorithm} = key;
  const multikey = new Uint8Array(2 + key._seedBytes.length);
  setSecretKeySeedHeader({algorithm, buffer: multikey});
  multikey.set(key._seedBytes, 2);
  return MULTIBASE_BASE64URL_HEADER + base64url.encode(multikey);
}

// ensures public and secret key headers belong to the same algorithm
function _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey}) {
  const publicKeyAlgorithm = getAlgorithmFromPublicMultikey({publicMultikey});
  const secretKeyAlgorithm = getAlgorithmFromSecretMultikey({secretMultikey});
  if(publicKeyAlgorithm !== secretKeyAlgorithm) {
    throw new Error(
      `Public key algorithm ('${publicKeyAlgorithm}') ` +
      `does not match secret key algorithm ('${secretKeyAlgorithm}').`);
  }
}

// maps JWK alg string to ALGORITHM constant
function _algorithmFromAlg(alg) {
  if(alg === ALGORITHM.MLDSA44) {
    return ALGORITHM.MLDSA44;
  }
  if(alg === ALGORITHM.MLDSA65) {
    return ALGORITHM.MLDSA65;
  }
  if(alg === ALGORITHM.MLDSA87) {
    return ALGORITHM.MLDSA87;
  }
  throw new TypeError(`Unsupported JWK alg "${alg}".`);
}
