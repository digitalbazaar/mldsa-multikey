/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import {
  ALGORITHM,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {createSigner, createVerifier} from './factory.js';
import {
  publicKeyBytesToKeyId,
  publicKeyMultibaseToKeyId
} from './helpers.js';
import {exportKeyAsJwk, generateKey, importKey} from './crypto.js';
import {
  exportKeyPair,
  importKeyPair,
  secretKeyToMultibase,
  toPublicKeyBytes,
  toPublicKeyMultibase,
} from './serialize.js';
import {toMultikey} from './translators.js';

// generates ML-DSA key pair
export async function generate({
  id, controller, algorithm: algorithmName = ALGORITHM.MLDSA44
} = {}) {
  const keyPair = generateKey(algorithmName);
  keyPair.secretKey = keyPair.secretKey;
  const keyPairInterface = await _createKeyPairInterface({keyPair});
  await keyPairInterface.export({publicKey: true});
  if(controller && !id) {
    const {publicKey: publicKeyBytes} =
      await keyPairInterface.export({publicKey: true, raw: true});
    id = `${controller}#${publicKeyBytesToKeyId({publicKeyBytes})}`;
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  return keyPairInterface;
}

// imports ML-DSA key pair from JSON Multikey
export async function from(key) {
  let multikey = {...key};
  if(multikey.type !== 'Multikey') {
    // attempt loading from JWK if `publicKeyJwk` is present
    if(multikey.publicKeyJwk) {
      let id;
      let controller;
      if(multikey.type === 'JsonWebKey') {
        ({id, controller} = multikey);
      }
      return fromJwk({jwk: multikey.publicKeyJwk, secretKey: false,
        id, controller});
    }
    if(multikey.type) {
      multikey = await toMultikey({keyPair: multikey});
      return _createKeyPairInterface({keyPair: multikey});
    }
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }

  if(multikey.controller && !multikey.id) {
    multikey.id = `${key.controller}#${
      publicKeyMultibaseToKeyId(
        {publicKeyMultibase: key.publicKeyMultibase})}`;
  }

  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

// imports key pair from JWK
export async function fromJwk({jwk, secretKey = false, id, controller} = {}) {
  const algorithm = jwk.alg;
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: toPublicKeyMultibase({jwk})
  };
  if(typeof id === 'string') {
    multikey.id = id;
  }
  if(typeof controller === 'string') {
    multikey.controller = controller;
  }
  if(secretKey && jwk.priv) {
    // import the JWK to get the expanded secret key bytes, then encode
    const key = importKey('jwk', jwk, algorithm);
    multikey.secretKeyMultibase = secretKeyToMultibase({key});
  }
  return from(multikey);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  if(!keyPair?.publicKey?.algorithm) {
    keyPair = importKeyPair(keyPair);
  }
  const useSecretKey = secretKey && !!keyPair.secretKey;
  if(useSecretKey) {
    // include pub (public key bytes) alongside priv (seed) for a complete JWK
    const jwk = exportKeyAsJwk(keyPair.secretKey);
    jwk.pub = exportKeyAsJwk(keyPair.publicKey).pub;
    return jwk;
  }
  return exportKeyAsJwk(keyPair.publicKey);
}

// raw import from publicKey bytes and optional secretKey seed bytes
export async function fromRaw({
  algorithm: algorithmName = ALGORITHM.MLDSA44, secretKey, publicKey
} = {}) {
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  const pubKey = importKey('raw-public', publicKey, algorithmName);
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: toPublicKeyMultibase({jwk: exportKeyAsJwk(pubKey)})
  };
  if(secretKey) {
    // secretKey must be the 32-byte seed
    const secKey = importKey('raw-seed', secretKey, algorithmName);
    multikey.secretKeyMultibase = secretKeyToMultibase({key: secKey});
  }
  return from(multikey);
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair}) {
  if(!keyPair?.publicKey?.algorithm) {
    keyPair = importKeyPair(keyPair);
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true, raw = false
  } = {}) => {
    if(raw) {
      const result = {};
      if(publicKey) {
        const jwk = exportKeyAsJwk(keyPair.publicKey);
        result.publicKey = toPublicKeyBytes({jwk});
      }
      if(secretKey) {
        result.secretKey = new Uint8Array(keyPair.secretKey._keyBytes);
      }
      return result;
    }
    return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
  };
  const {publicKeyMultibase, secretKeyMultibase} = await exportFn({
    publicKey: true, secretKey: true, includeContext: true
  });
  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
    },
    // eslint-disable-next-line no-unused-vars
    async deriveSecret({publicKey, remotePublicKey} = {}) {
      const error = Error('"keyAgreement" is not supported by ML-DSA.');
      error.name = 'NotSupportedError';
      throw error;
    }
  };

  return keyPair;
}

// checks if key pair is in Multikey format
function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new TypeError('"key" must be a Multikey with type "Multikey".');
  }
  if(!(key['@context'] === MULTIKEY_CONTEXT_V1_URL ||
    (Array.isArray(key['@context']) &&
    key['@context'].includes(MULTIKEY_CONTEXT_V1_URL)))) {
    throw new TypeError(
      '"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}
