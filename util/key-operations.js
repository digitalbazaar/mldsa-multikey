/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {NIST_SECURITY_LEVEL_2} from '../lib/constants.js';
import * as MldsaMultikey from '../lib/index.js';
import {stringToUint8Array} from '../test/text-encoder.js';

// generates ECDSA key pair
async function generateKeyPair(options = {}) {
  if(!options.nistSecurityLevel) {
    options.nistSecurityLevel = NIST_SECURITY_LEVEL_2;
  }
  if(!options.controller) {
    options.controller = 'did:example:1234';
  }
  return MldsaMultikey.generate(options);
}

// executes common key operations
async function main() {
  const keyPair = await generateKeyPair();
  console.log('raw key pair:', keyPair);
  const exportedKeyPair = await keyPair.export({
    publicKey: true,
    secretKey: true,
    includeContext: true
  });
  console.log('exported key pair:', exportedKeyPair);
  const signer = keyPair.signer();
  const verifier = keyPair.verifier();
  const rawData = 'key operations test';
  const data = stringToUint8Array(rawData);
  const signature = await signer.sign({data});
  console.log('signature:', base58.encode(new Uint8Array(signature)));
  const result = await verifier.verify({data, signature});
  console.log('result:', result);
}

main();
