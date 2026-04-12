/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  CryptoKey,
  mldsaExportKey,
  mldsaGenerateKey,
  mldsaImportKey,
  mldsaSign,
  mldsaVerify,
  resolveNistSecurityLevel,
} from './crypto-util.js';

// Extends the browser's native subtle crypto with ML-DSA support. Non-ML-DSA
// operations are delegated to the native window.crypto / self.crypto.
class MldsaSubtleCrypto {
  constructor(nativeSubtle) {
    this._native = nativeSubtle;
  }

  async encrypt(algorithm, key, data) {
    return this._native.encrypt(algorithm, key, data);
  }

  async decrypt(algorithm, key, data) {
    return this._native.decrypt(algorithm, key, data);
  }

  async digest(algorithm, data) {
    return this._native.digest(algorithm, data);
  }

  async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable,
    keyUsages) {
    return this._native.deriveKey(
      algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages);
  }

  async deriveBits(algorithm, baseKey, length) {
    return this._native.deriveBits(algorithm, baseKey, length);
  }

  async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
    return this._native.wrapKey(format, key, wrappingKey, wrapAlgorithm);
  }

  async unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
    unwrappedKeyAlgorithm, extractable, keyUsages) {
    return this._native.unwrapKey(
      format, wrappedKey, unwrappingKey, unwrapAlgorithm,
      unwrappedKeyAlgorithm, extractable, keyUsages);
  }

  async sign(algorithm, key, data) {
    if(key instanceof CryptoKey) {
      return mldsaSign(key, data);
    }
    return this._native.sign(algorithm, key, data);
  }

  async verify(algorithm, key, signature, data) {
    if(key instanceof CryptoKey) {
      return mldsaVerify(key, signature, data);
    }
    return this._native.verify(algorithm, key, signature, data);
  }

  async generateKey(algorithm, extractable, keyUsages) {
    if(_isMldsaAlgorithm(algorithm)) {
      const seed = new Uint8Array(32);
      (self.crypto ?? window.crypto).getRandomValues(seed);
      return mldsaGenerateKey(algorithm, extractable, keyUsages, seed);
    }
    return this._native.generateKey(algorithm, extractable, keyUsages);
  }

  async importKey(format, keyData, algorithm, extractable, keyUsages) {
    if(_isMldsaAlgorithm(algorithm)) {
      return mldsaImportKey(format, keyData, algorithm, extractable, keyUsages);
    }
    return this._native.importKey(format, keyData, algorithm, extractable,
      keyUsages);
  }

  async exportKey(format, key) {
    if(key instanceof CryptoKey) {
      return mldsaExportKey(format, key);
    }
    return this._native.exportKey(format, key);
  }
}

// Extended crypto object that wraps the browser's native crypto.
class BrowserCrypto {
  constructor(nativeCrypto) {
    this._native = nativeCrypto;
    this.subtle = new MldsaSubtleCrypto(nativeCrypto.subtle);
  }

  getRandomValues(typedArray) {
    return this._native.getRandomValues(typedArray);
  }

  randomUUID() {
    return this._native.randomUUID();
  }
}

function _isMldsaAlgorithm(algorithm) {
  if(!algorithm) {
    return false;
  }
  try {
    resolveNistSecurityLevel(algorithm);
    return true;
  } catch(e) {
    return false;
  }
}

const _nativeCrypto = self.crypto ?? window.crypto;
export const webcrypto = new BrowserCrypto(_nativeCrypto);
export {CryptoKey};
