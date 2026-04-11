/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  NIST_SECURITY_LEVEL_2,
  MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER,
  MULTICODEC_MLDSA44_SECRET_KEY_HEADER,
} from './constants.js';

// retrieves name of appropriate NIST security level from public Multikey
export function getNistSecurityLevelFromPublicMultikey({publicMultikey}) {
  if(publicMultikey[0] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[1]) {
    return NIST_SECURITY_LEVEL_2;
  }

  throw new TypeError('Unsupported public multikey header.');
}

// retrieves name of appropriate NIST security level from secret Multikey
export function getNistSecurityLevelFromSecretMultikey({secretMultikey}) {
  if(secretMultikey[0] === MULTICODEC_MLDSA44_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_MLDSA44_SECRET_KEY_HEADER[1]) {
    return NIST_SECURITY_LEVEL_2;
  }

  throw new TypeError('Unsupported secret multikey header.');
}

// retrieves byte size of secret key
export function getSecretKeySize({nistSecurityLevel}) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    return 2560;
  }

  throw new TypeError(`Unsupported nistSecurityLevel "${nistSecurityLevel}".`);
}

// sets secret key header bytes on key pair
export function setSecretKeyHeader({nistSecurityLevel, buffer}) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    buffer[0] = MULTICODEC_MLDSA44_SECRET_KEY_HEADER[0];
    buffer[1] = MULTICODEC_MLDSA44_SECRET_KEY_HEADER[1];
  } else {
    throw new TypeError(
      `Unsupported NIST security level "${nistSecurityLevel}".`);
  }
}

// sets public key header bytes on key pair
export function setPublicKeyHeader({nistSecurityLevel, buffer}) {
  if(nistSecurityLevel === NIST_SECURITY_LEVEL_2) {
    buffer[0] = MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[0];
    buffer[1] = MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[1];
  } else {
    throw new TypeError(
      `Unsupported NIST security level "${nistSecurityLevel}".`);
  }
}
