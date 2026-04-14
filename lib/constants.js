/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
// Name of algorithm
export const ALGORITHM = {
  MLDSA44: 'ML-DSA-44'
};
// Determines whether key pair is extractable
export const EXTRACTABLE = true;
// Multikey context v1 URL
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
export const MULTIKEY_TYPE = 'Multikey';
export const MULTIBASE_BASE58_HEADER = 'z';
export const MULTIBASE_BASE64URL_HEADER = 'u';

// Multicodec ML-DSA 44 (0x1210 varint -> 0x9024 hex)
export const MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER =
  new Uint8Array([0x90, 0x24]);

// Multicodec ML-DSA-44 secret key header (0x1317 varint -> 0x9726 hex)
export const MULTICODEC_MLDSA44_SECRET_KEY_HEADER =
  new Uint8Array([0x97, 0x26]);

// MLDSA hash function for ML-DSA-44
export const MLDSA44_HASH = 'SHA-256';
