/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {randomBytes} from 'node:crypto';
import {
  CryptoKey,
  mldsaExportKey,
  mldsaGenerateKey,
  mldsaImportKey,
  mldsaSign,
  mldsaVerify,
} from './crypto-util.js';

class SubtleCrypto {
  /* eslint-disable no-unused-vars */
  async encrypt(algorithm, key, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async decrypt(algorithm, key, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  async sign(algorithm, key, data) {
    return mldsaSign(key, data);
  }

  async verify(algorithm, key, signature, data) {
    return mldsaVerify(key, signature, data);
  }

  /* eslint-disable no-unused-vars */
  async digest(algorithm, data) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  async generateKey(algorithm, extractable, keyUsages) {
    const seed = new Uint8Array(randomBytes(32));
    return mldsaGenerateKey(algorithm, extractable, keyUsages, seed);
  }

  /* eslint-disable no-unused-vars */
  async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable,
    keyUsages) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async deriveBits(algorithm, baseKey, length) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */

  async importKey(format, keyData, algorithm, extractable, keyUsages) {
    return mldsaImportKey(format, keyData, algorithm, extractable, keyUsages);
  }

  async exportKey(format, key) {
    return mldsaExportKey(format, key);
  }

  /* eslint-disable no-unused-vars */
  async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }

  async unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
    unwrappedKeyAlgorithm, extractable, keyUsages) {
    throw new DOMException('Not implemented', 'NotSupportedError');
  }
  /* eslint-enable no-unused-vars */
}

// Crypto matches the Web Crypto API Crypto interface:
// https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto
class Crypto {
  constructor() {
    this.subtle = new SubtleCrypto();
  }

  // Fills the given TypedArray with cryptographically strong random values.
  getRandomValues(typedArray) {
    const bytes = randomBytes(typedArray.byteLength);
    typedArray.set(new typedArray.constructor(
      bytes.buffer, bytes.byteOffset, typedArray.length));
    return typedArray;
  }

  // Returns a randomly generated UUID v4 string.
  randomUUID() {
    const bytes = randomBytes(16);
    // Set version 4 bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant bits
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-` +
      `${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
}

export const webcrypto = new Crypto();
export {CryptoKey};
