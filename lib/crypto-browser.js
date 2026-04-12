/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
// eslint-disable-next-line no-undef
export const webcrypto = globalThis.crypto;
// eslint-disable-next-line no-undef
export const CryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
