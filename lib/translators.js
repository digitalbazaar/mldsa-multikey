/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  MULTIKEY_TYPE,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';

// valid MLDSA types
const VALID_MLDSA_TYPES = new Set([
  MULTIKEY_TYPE
]);

// converts key pair to Multikey format
export async function toMultikey({keyPair}) {
  if(!VALID_MLDSA_TYPES.has(keyPair.type)) {
    throw new TypeError(`Unsupported key type "${keyPair.type}".`);
  }

  return {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    id: keyPair.id,
    type: 'Multikey',
    controller: keyPair.controller,
    publicKeyMultibase: keyPair.publicKeyMultibase,
    secretKeyMultibase: keyPair.secretKeyMultibase
  };
}
