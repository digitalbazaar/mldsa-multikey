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

// Multicodec ML-DSA public key headers
// mldsa-44-pub (0x1210 varint -> [0x90, 0x24])
export const MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER =
  new Uint8Array([0x90, 0x24]);
// mldsa-65-pub (0x1211 varint -> [0x91, 0x24])
export const MULTICODEC_MLDSA65_PUBLIC_KEY_HEADER =
  new Uint8Array([0x91, 0x24]);
// mldsa-87-pub (0x1212 varint -> [0x92, 0x24])
export const MULTICODEC_MLDSA87_PUBLIC_KEY_HEADER =
  new Uint8Array([0x92, 0x24]);

// Multicodec ML-DSA private key headers (expanded key format)
// mldsa-44-priv (0x1317 varint -> [0x97, 0x26])
export const MULTICODEC_MLDSA44_SECRET_KEY_HEADER =
  new Uint8Array([0x97, 0x26]);
// mldsa-65-priv (0x1318 varint -> [0x98, 0x26])
export const MULTICODEC_MLDSA65_SECRET_KEY_HEADER =
  new Uint8Array([0x98, 0x26]);
// mldsa-87-priv (0x1319 varint -> [0x99, 0x26])
export const MULTICODEC_MLDSA87_SECRET_KEY_HEADER =
  new Uint8Array([0x99, 0x26]);

// Multicodec ML-DSA private key seed headers (32-byte seed format)
// mldsa-44-priv-seed (0x131a varint -> [0x9a, 0x26])
export const MULTICODEC_MLDSA44_SECRET_KEY_SEED_HEADER =
  new Uint8Array([0x9a, 0x26]);
// mldsa-65-priv-seed (0x131b varint -> [0x9b, 0x26])
export const MULTICODEC_MLDSA65_SECRET_KEY_SEED_HEADER =
  new Uint8Array([0x9b, 0x26]);
// mldsa-87-priv-seed (0x131c varint -> [0x9c, 0x26])
export const MULTICODEC_MLDSA87_SECRET_KEY_SEED_HEADER =
  new Uint8Array([0x9c, 0x26]);

// MLDSA hash function for ML-DSA-44
export const MLDSA44_HASH = 'SHA-256';
