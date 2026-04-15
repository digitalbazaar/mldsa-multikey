/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {MLDSA44_HASH, MLDSA65_HASH, MLDSA87_HASH} from './constants.js';
import {sign, verify} from './crypto.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const name = secretKey.algorithm;
  const algorithm = {name, hash: {name: _getMldsaHash(name)}};
  return {
    algorithm,
    id,
    async sign({data} = {}) {
      return new Uint8Array(sign(secretKey, data));
    }
  };
}

// exposes verify method
export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const name = publicKey.algorithm;
  const algorithm = {name, hash: {name: _getMldsaHash(name)}};
  return {
    algorithm,
    id,
    async verify({data, signature} = {}) {
      return verify(publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ML-DSA hash function
function _getMldsaHash(algorithmName) {
  if(algorithmName === 'ML-DSA-44') {
    return MLDSA44_HASH;
  }
  if(algorithmName === 'ML-DSA-65') {
    return MLDSA65_HASH;
  }
  if(algorithmName === 'ML-DSA-87') {
    return MLDSA87_HASH;
  }
  throw new TypeError(`Unsupported algorithm "${algorithmName}".`);
}
