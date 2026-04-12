/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM, NIST_SECURITY_LEVEL_2, MLDSA_HASH} from './constants.js';
import {webcrypto} from './crypto.js';

// returns algorithm name for a given NIST security level
function _getAlgorithmName(nistSecurityLevel) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    return ALGORITHM.MLDSA44;
  }
  return 'ML-DSA-UNKNOWN';
}

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const {nistSecurityLevel} = secretKey.algorithm;
  const name = _getAlgorithmName(nistSecurityLevel);
  const algorithm = {
    name,
    hash: {name: _getMldsaHash({nistSecurityLevel})}};
  return {
    algorithm,
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
  const name = _getAlgorithmName(nistSecurityLevel);
  const algorithm = {
    name,
    hash: {name: _getMldsaHash({nistSecurityLevel})}
  };
  return {
    algorithm,
    id,
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ML-DSA hash function
function _getMldsaHash({nistSecurityLevel}) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    return MLDSA_HASH.SHA256;
  }
  throw new TypeError(
    `Unsupported NIST Security Level "${nistSecurityLevel}".`);
}
