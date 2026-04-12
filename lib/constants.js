/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
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

// Multicodec p256-priv header (0x1317 varint -> 0x9726 hex)
export const MULTICODEC_MLDSA44_SECRET_KEY_HEADER =
  new Uint8Array([0x97, 0x26]);

// Supported NIST Security Levels
export const NIST_SECURITY_LEVEL_2 = 2;

// MLDSA hash functions
export const MLDSA_HASH = {
  SHA256: 'SHA-256',
  SHA384: 'SHA-384',
  SHA512: 'SHA-512'
};
