# ML-DSA Multikey Library _(@digitalbazaar/mldsa-multikey)_

[![Build status](https://img.shields.io/github/actions/workflow/status/digitalbazaar/mldsa-multikey/main.yml)](https://github.com/digitalbazaar/mldsa-multikey/actions?query=workflow%3A%22Node.js+CI%22)
[![Coverage status](https://img.shields.io/codecov/c/github/digitalbazaar/mldsa-multikey)](https://codecov.io/gh/digitalbazaar/mldsa-multikey)
[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/mldsa-multikey.svg)](https://npm.im/@digitalbazaar/mldsa-multikey)

> Javascript library for generating and working with MldsaMultikey key pairs.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

For use with:

* [`@digitalbazaar/mldsa44-rdfc-2024-cryptosuite`](https://github.com/digitalbazaar/mldsa44-rdfc-2024-cryptosuite) `^1.0.0`
  crypto suite (with [`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures) `^11.0.0`)
* [`@digitalbazaar/data-integrity`](https://github.com/digitalbazaar/data-integrity) `^1.0.0`

See also (related specs):

* [Verifiable Credential Data Integrity](https://w3c.github.io/vc-data-integrity/)

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 22+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/mldsa-multikey.git
cd mldsa-multikey
npm install
```

## Usage

### Generating a new public/secret key pair

To generate a new public/secret key pair:

* `{number} [nistSecurityLevel]` \[Required\] Desired NIST security level used to generate the key:
  \[2\].
* `{string} [id]` \[Optional\] ID for the generated key.
* `{string} [controller]` \[Optional\] Controller URI or DID to initialize the
  generated key. (This will be used to generate `id` if it is not explicitly defined.)

```js
import * as MldsaMultikey from '@digitalbazaar/mldsa-multikey';

const keyPair = await MldsaMultikey.generate({nistSecurityLevel: 2});
```

### Importing a key pair from storage

To create an instance of a public/secret key pair from data imported from
storage, use `.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await MldsaMultikey.from(serializedKeyPair);
````

### Exporting the public key only

To export just the public key of a pair:

```js
await keyPair.export({publicKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#zQmartQdEuERvHcqLnjGTiNkCfAW7LqvLBEofCnETp6FtNp',
  controller: 'did:example:1234',
  publicKeyMultibase: 'ukCQbQWUQXUiqckKYr2NHC2E6QrYgnUSZkmu28lnISswW5fHA1E4JJYb...'
}
```

### Exporting the full public-secret key pair

To export the full key pair, including secret key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
await keyPair.export({publicKey: true, secretKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#zQmartQdEuERvHcqLnjGTiNkCfAW7LqvLBEofCnETp6FtNp',
  controller: 'did:example:1234',
  publicKeyMultibase: 'ukCQbQWUQXUiqckKYr2NHC2E6QrYgnUSZkmu28lnISswW5fHA1E4JJYb...',
  secretKeyMultibase: 'ulyYbQWUQXUiqckKYr2NHC2E6QrYgnUSZkmu28lnISswW5W8sui0fd84f...'
}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = MldsaMultikey.generate({nistSecurityLevel: 2});

const {sign} = keyPair.signer();

// data is a Uint8Array of bytes
const data = (new TextEncoder()).encode('test data goes here');
// Signing also outputs a Uint8Array, which you can serialize to text etc.
const signature = await sign({data});
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = MldsaMultikey.generate({nistSecurityLevel: 2});

const {verify} = keyPair.verifier();

const valid = await verify({data, signature});
// true
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © 2026 Digital Bazaar
