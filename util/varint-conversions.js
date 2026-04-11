/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import varint from 'varint';

// converts varint to hex
function vintToHex(data) {
  if(typeof data !== 'number') {
    throw new TypeError('"data" must be a number.');
  }
  return varint.encode(data);
}

// converts ECDSA key headers from varint to hex
function main() {
  console.log('varint -> hex:');
  console.log(`0x1210 -> 0x${Buffer.from(vintToHex(0x1210)).toString('hex')}`);
  console.log(`0x1317 -> 0x${Buffer.from(vintToHex(0x1317)).toString('hex')}`);
}

main();
