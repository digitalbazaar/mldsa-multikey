/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL,
  NIST_SECURITY_LEVEL_2
} from './constants.js';
import {CryptoKey, webcrypto} from './crypto.js';
import {createSigner, createVerifier} from './factory.js';
import {publicKeyBytesToMultihashKeyId} from './helpers.js';
import {
  cryptoKeyfromRaw,
  exportKeyPair, importKeyPair,
  toPublicKeyBytes, toSecretKeyBytes,
  toPublicKeyMultibase, toSecretKeyMultibase
} from './serialize.js';

// generates ML-DSA key pair
export async function generate({id, controller, nistSecurityLevel = 2} = {}) {
  const algorithm = {name: 'MLDSA', nistSecurityLevel};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign', 'verify']);
  keyPair.secretKey = keyPair.privateKey;
  delete keyPair.privateKey;
  const keyPairInterface = await _createKeyPairInterface({keyPair});
  await keyPairInterface.export({publicKey: true});
  if(controller && !id) {
    const {publicKey: publicKeyBytes} =
      await keyPairInterface.export({publicKey: true, raw: true});
    id = `${controller}#${publicKeyBytesToMultihashKeyId({publicKeyBytes})}`;
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  return keyPairInterface;
}

// imports ML-DSA-44 key pair from JSON Multikey
export async function from(key) {
  const multikey = {...key};
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
    throw new TypeError(`Unsupported key type "${multikey.type}".`);
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  if(multikey.controller && !multikey.id) {
    multikey.id = `${key.controller}#${key.publicKeyMultibase}`;
  }

  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

// imports key pair from JWK
export async function fromJwk({jwk, secretKey = false, id, controller} = {}) {
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
    multikey.secretKeyMultibase = toSecretKeyMultibase({jwk});
  }
  return from(multikey);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return jwk;
}

// raw import from secretKey and/or publicKey bytes
export async function fromRaw({
  nistSecurityLevel = NIST_SECURITY_LEVEL_2, secretKey, publicKey
} = {}) {
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  const cryptoKey = await cryptoKeyfromRaw({nistSecurityLevel,
    secretKey, publicKey});
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return fromJwk({jwk, secretKey: !!secretKey});
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true, raw = false
  } = {}) => {
    if(raw) {
      const jwk = await toJwk({keyPair, secretKey});
      const result = {};
      if(publicKey) {
        result.publicKey = toPublicKeyBytes({jwk});
      }
      if(secretKey) {
        result.secretKey = toSecretKeyBytes({jwk});
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
