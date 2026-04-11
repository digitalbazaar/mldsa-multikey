/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {createHash} from 'node:crypto';
import * as base58 from 'base58-universal';
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

// creates a base58btc-encoded multihash key id fragment from raw public key
// bytes; uses SHA-256 (0x12) multihash header
export function publicKeyBytesToMultihashKeyId({publicKeyBytes}) {
  const digest = createHash('sha256').update(publicKeyBytes).digest();
  const multihash = new Uint8Array(2 + digest.length);
  multihash[0] = 0x12;
  multihash[1] = 0x20;
  multihash.set(digest, 2);
  return 'z' + base58.encode(multihash);
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
