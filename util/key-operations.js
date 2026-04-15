/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {ALGORITHM} from '../lib/constants.js';
import * as MldsaMultikey from '../lib/index.js';
import {stringToUint8Array} from '../test/text-encoder.js';

// executes common key operations for a single algorithm
async function runKeyOperations(algorithm) {
  console.log(`\n=== ${algorithm} ===`);
  const keyPair = await MldsaMultikey.generate({
    algorithm,
    controller: 'did:example:1234'
  });
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

async function main() {
  for(const algorithm of Object.values(ALGORITHM)) {
    await runKeyOperations(algorithm);
  }
}

main();
