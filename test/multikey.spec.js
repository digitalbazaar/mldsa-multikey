/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */

import {multikeys} from './mock-data.js';
import {
  testAlgorithm,
  testExport,
  testFrom,
  testGenerate,
  testJWK,
  testRaw,
  testSignVerify
} from './assertions.js';

describe('mldsa-multikey', function() {
  for(const [keyType, options] of multikeys) {
    const {
      id,
      serializedKeyPair,
      props
    } = options;
    describe(keyType, function() {
      describe('algorithm', function() {
        testAlgorithm({keyType, serializedKeyPair});
      });
      describe('generate', function() {
        testGenerate({keyType, ...props});
      });
      describe('export', () => {
        testExport({keyType});
      });
      describe('sign and verify', function() {
        testSignVerify({id, serializedKeyPair, keyType});
      });
      describe('from', function() {
        testFrom({keyType, id, serializedKeyPair});
      });
      describe('fromJwk/toJwk', () => {
        testJWK({keyType});
      });
      describe('fromRaw', () => {
        testRaw({keyType});
      });
    });
  }
});
