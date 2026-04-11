/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM, NIST_SECURITY_LEVEL_2, MLDSA_HASH} from './constants.js';
import {webcrypto} from './crypto.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const {nistSecurityLevel} = secretKey.algorithm;
  const algorithm = {
    name: ALGORITHM,
    hash: {name: _getMldsaHash({nistSecurityLevel})}};
  return {
    algorithm: nistSecurityLevel,
    id,
    async sign({data} = {}) {
      return new Uint8Array(await webcrypto.subtle.sign(
        algorithm, secretKey, data));
    }
  };
}

// exposes verify method
export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const {nistSecurityLevel} = publicKey.algorithm;
  const algorithm = {
    name: ALGORITHM,
    hash: {name: _getMldsaHash({nistSecurityLevel})}
  };
  return {
    algorithm: nistSecurityLevel,
    id,
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ECDSA hash function
function _getMldsaHash({nistSecurityLevel}) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    return MLDSA_HASH.SHA256;
  }
  throw new TypeError(
    `Unsupported NIST Security Level "${nistSecurityLevel}".`);
}
