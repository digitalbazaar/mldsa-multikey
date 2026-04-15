/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import {sign, verify} from './mldsa.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const algorithm = secretKey.algorithm;
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
  const algorithm = publicKey.algorithm;
  return {
    algorithm,
    id,
    async verify({data, signature} = {}) {
      return verify(publicKey, signature, data);
    }
  };
}
