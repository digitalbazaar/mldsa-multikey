/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import varint from 'varint';

// converts varint to hex
function vintToHex(data) {
  if(typeof data !== 'number') {
    throw new TypeError('"data" must be a number.');
  }
  return varint.encode(data);
}

// helper to format a single entry
function fmt(hex, label) {
  const encoded = `0x${Buffer.from(vintToHex(hex)).toString('hex')}`;
  const paddedHex = hex.toString(16).toUpperCase().padStart(4, '0');
  console.log(`0x${paddedHex} (${label}) -> ${encoded}`);
}

// converts ML-DSA key headers from varint to hex
function main() {
  console.log('varint -> hex:');

  console.log('-- public keys --');
  fmt(0x1210, 'mldsa-44-pub');
  fmt(0x1211, 'mldsa-65-pub');
  fmt(0x1212, 'mldsa-87-pub');

  console.log('-- private keys (expanded) --');
  fmt(0x1317, 'mldsa-44-priv');
  fmt(0x1318, 'mldsa-65-priv');
  fmt(0x1319, 'mldsa-87-priv');

  console.log('-- private key seeds --');
  fmt(0x131a, 'mldsa-44-priv-seed');
  fmt(0x131b, 'mldsa-65-priv-seed');
  fmt(0x131c, 'mldsa-87-priv-seed');
}

main();
