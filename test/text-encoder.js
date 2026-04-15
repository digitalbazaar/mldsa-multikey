/*
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
// converts data from string to Uint8Array
export function stringToUint8Array(data) {
  if(typeof data === 'string') {
    return new TextEncoder().encode(data);
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.');
  }
  return data;
}
