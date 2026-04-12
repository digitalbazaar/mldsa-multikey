/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import chai from 'chai';
import * as MldsaMultikey from '../lib/index.js';
import {stringToUint8Array} from './text-encoder.js';
import {CryptoKey} from '../lib/crypto.js';
import {webcrypto} from '../lib/crypto.js';
import {exportKeyPair} from '../lib/serialize.js';
import {
  MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER
} from '../lib/constants.js';

const {expect} = chai;

export function testSignVerify({id, serializedKeyPair}) {
  let signer;
  let verifier;
  before(async function() {
    const keyPair = await MldsaMultikey.from({
      id,
      ...serializedKeyPair
    });
    signer = keyPair.signer();
    verifier = keyPair.verifier();
  });
  it('should have correct id', function() {
    signer.should.have.property('id', id);
    verifier.should.have.property('id', id);
  });
  it('should sign & verify', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('has proper signature format', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    expect(signature).to.be.instanceof(Uint8Array);
  });

  it('fails if signing data is changed', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
}

export function testAlgorithm({serializedKeyPair, keyType}) {
  it('signer() instance should export proper algorithm', async () => {
    const keyPair = await MldsaMultikey.from(serializedKeyPair);
    const signer = keyPair.signer();
    signer.algorithm.name.should.equal(keyType);
  });
  it('verifier() instance should export proper algorithm', async () => {
    const keyPair = await MldsaMultikey.from(serializedKeyPair);
    const verifier = keyPair.verifier();
    verifier.algorithm.name.should.equal(keyType);
  });
}

export function testGenerate({
  nistSecurityLevel,
  // public key: 2-byte header + 1312-byte key
  publicKeyByteLength = 1314,
  // secret key: 2-byte header + 2560-byte expanded key
  secretKeyByteLength = 2562
}) {
  it('should generate a key pair', async function() {
    let keyPair;
    let err;
    try {
      keyPair = await MldsaMultikey.generate({nistSecurityLevel});
    } catch(e) {
      err = e;
    }
    expect(err).to.not.exist;
    expect(keyPair).to.have.property('publicKeyMultibase');
    expect(keyPair).to.have.property('secretKeyMultibase');
    expect(keyPair).to.have.property('publicKey');
    expect(keyPair?.publicKey instanceof CryptoKey).to.be.true;
    expect(keyPair).to.have.property('secretKey');
    expect(keyPair?.secretKey instanceof CryptoKey).to.be.true;
    expect(keyPair).to.have.property('export');
    expect(keyPair).to.have.property('signer');
    expect(keyPair).to.have.property('verifier');
    // keys use base64url multibase (u prefix)
    expect(keyPair.publicKeyMultibase[0]).to.equal('u');
    expect(keyPair.secretKeyMultibase[0]).to.equal('u');
    const publicKeyBytes = base64url.decode(
      keyPair.publicKeyMultibase.slice(1));
    const secretKeyBytes = base64url.decode(
      keyPair.secretKeyMultibase.slice(1));
    publicKeyBytes.length.should.equal(
      publicKeyByteLength,
      `Expected publicKey byte length to be ${publicKeyByteLength}.`);
    secretKeyBytes.length.should.equal(
      secretKeyByteLength,
      `Expected secretKey byte length to be ${secretKeyByteLength}.`);
  });
}

export function testExport({nistSecurityLevel}) {
  it('should export id, type and key material', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      controller: 'did:example:1234',
      nistSecurityLevel
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });

    const expectedProperties = [
      'id', 'type', 'controller', 'publicKeyMultibase', 'secretKeyMultibase'
    ];
    for(const property of expectedProperties) {
      expect(keyPairExported).to.have.property(property);
      expect(keyPairExported[property]).to.exist;
    }

    expect(keyPairExported.controller).to.equal('did:example:1234');
    expect(keyPairExported.type).to.equal('Multikey');
    expect(keyPairExported.id).to.equal('4e0db4260c87cc200df3');
  });

  it('should only export public key if specified', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      nistSecurityLevel
    });
    const keyPairExported = await keyPair.export({publicKey: true});

    expect(keyPairExported).not.to.have.property('secretKeyMultibase');
    expect(keyPairExported).to.have.property('publicKeyMultibase');
    expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
    expect(keyPairExported).to.have.property('type', 'Multikey');
  });

  it('should only export public key if no secret key available', async () => {
    const algorithm = {name: 'ML-DSA-44', nistSecurityLevel: 2};
    const rawKeyPair = await webcrypto.subtle.generateKey(
      algorithm, true, ['sign', 'verify']);
    // simulate a key pair with only a public key
    const keyPairNoSecret = {
      publicKey: rawKeyPair.publicKey
    };

    const keyPairExported = await exportKeyPair({
      keyPair: keyPairNoSecret,
      publicKey: true,
      secretKey: true,
      includeContext: true
    });

    expect(keyPairExported).not.to.have.property('secretKeyMultibase');
  });

  it('should export raw public key', async () => {
    const keyPair = await MldsaMultikey.generate({nistSecurityLevel});
    // decode multibase, strip 2-byte multicodec header to get raw key
    const expectedPublicKey = base64url.decode(
      keyPair.publicKeyMultibase.slice(1)).slice(2);
    const {publicKey} = await keyPair.export({publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey);
  });

  it('should export raw secret key', async () => {
    const keyPair = await MldsaMultikey.generate({nistSecurityLevel});
    // decode multibase, strip 2-byte multicodec header to get raw key
    const expectedSecretKey = base64url.decode(
      keyPair.secretKeyMultibase.slice(1)).slice(2);
    const {secretKey} = await keyPair.export({secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey);
  });
}

export function testFrom({serializedKeyPair, id}) {
  it('should auto-set key.id based on controller', async () => {
    const {publicKeyMultibase} = serializedKeyPair;
    const keyPair = await MldsaMultikey.from(serializedKeyPair);
    _ensurePublicKeyEncoding({keyPair, publicKeyMultibase});
    expect(keyPair.id).to.equal(id);
  });
  it('should round-trip load exported keys', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3'
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });
    const keyPairImported = await MldsaMultikey.from(keyPairExported);

    expect(await keyPairImported.export({publicKey: true, secretKey: true}))
      .to.eql(keyPairExported);
  });

  it('should import with `@context` array', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3'
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });
    const keyPairImported = await MldsaMultikey.from({
      ...keyPairExported,
      '@context': [{}, keyPairExported['@context']]
    });

    expect(await keyPairImported.export({publicKey: true, secretKey: true}))
      .to.eql(keyPairExported);
  });
  it('should load `publicKeyJwk`', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3'
    });
    const jwk1 = await MldsaMultikey.toJwk({keyPair});
    expect(jwk1.priv).to.not.exist;
    const keyPairImported1 = await MldsaMultikey.from({publicKeyJwk: jwk1});
    const keyPairImported2 = await MldsaMultikey.from({
      type: 'JsonWebKey',
      publicKeyJwk: jwk1
    });
    const jwk2 = await MldsaMultikey.toJwk({keyPair: keyPairImported1});
    const jwk3 = await MldsaMultikey.toJwk({keyPair: keyPairImported2});
    expect(jwk1).to.eql(jwk2);
    expect(jwk1).to.eql(jwk3);
  });
}

export function testJWK({nistSecurityLevel}) {
  it('should round-trip secret JWKs', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      nistSecurityLevel
    });
    const jwk1 = await MldsaMultikey.toJwk({keyPair, secretKey: true});
    expect(jwk1.priv).to.exist;
    const keyPairImported = await MldsaMultikey.fromJwk(
      {jwk: jwk1, secretKey: true});
    const jwk2 = await MldsaMultikey.toJwk(
      {keyPair: keyPairImported, secretKey: true});
    expect(jwk1).to.eql(jwk2);
  });

  it('should round-trip public JWKs', async () => {
    const keyPair = await MldsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      nistSecurityLevel
    });
    const jwk1 = await MldsaMultikey.toJwk({keyPair});
    expect(jwk1.priv).to.not.exist;
    const keyPairImported = await MldsaMultikey.fromJwk({jwk: jwk1});
    const jwk2 = await MldsaMultikey.toJwk({keyPair: keyPairImported});
    expect(jwk1).to.eql(jwk2);
  });
}

export function testRaw({nistSecurityLevel}) {
  it('should import raw public key', async () => {
    const keyPair = await MldsaMultikey.generate({nistSecurityLevel});

    // first export
    const expectedPublicKey = base64url.decode(
      keyPair.publicKeyMultibase.slice(1)).slice(2);
    const {publicKey} = await keyPair.export({publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey);

    // then import
    const imported = await MldsaMultikey.fromRaw(
      {nistSecurityLevel, publicKey});

    // then re-export to confirm
    const {publicKey: publicKey2} = await imported.export(
      {publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey2);
  });

  it('should import raw secret key', async () => {
    const keyPair = await MldsaMultikey.generate({nistSecurityLevel});

    // first export
    const expectedSecretKey = base64url.decode(
      keyPair.secretKeyMultibase.slice(1)).slice(2);
    const {secretKey, publicKey} = await keyPair.export(
      {secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey);

    // then import
    const imported = await MldsaMultikey.fromRaw(
      {nistSecurityLevel, secretKey, publicKey});

    // then re-export to confirm
    const {secretKey: secretKey2} = await imported.export(
      {secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey2);
  });
}

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  // ML-DSA public keys use base64url multibase (u prefix)
  keyPair.publicKeyMultibase.startsWith('u').should.be.true;
  publicKeyMultibase.startsWith('u').should.be.true;
  const decodedPubkey = base64url.decode(publicKeyMultibase.slice(1));
  // verify ML-DSA-44 multicodec header [0x90, 0x24]
  decodedPubkey[0].should.equal(MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[0]);
  decodedPubkey[1].should.equal(MULTICODEC_MLDSA44_PUBLIC_KEY_HEADER[1]);
  const encodedPubkey = 'u' + base64url.encode(decodedPubkey);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
