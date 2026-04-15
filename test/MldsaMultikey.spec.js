/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import * as MldsaMultikey from '../lib/index.js';
import chai from 'chai';

const should = chai.should();
const {expect} = chai;

describe('MldsaMultikey', () => {
  describe('module', () => {
    it('should have proper exports', async () => {
      expect(MldsaMultikey).to.have.property('generate');
      expect(MldsaMultikey).to.have.property('from');
      expect(MldsaMultikey).to.have.property('fromJwk');
      expect(MldsaMultikey).to.have.property('toJwk');
    });
  });

  describe('algorithm', () => {
    it('deriveSecret() should not be supported', async () => {
      const keyPair = await MldsaMultikey.generate({algorithm: 'ML-DSA-44'});

      let err;
      try {
        await keyPair.deriveSecret({publicKey: keyPair});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotSupportedError');
    });
  });

  describe('from', () => {
    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        await MldsaMultikey.from({});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.an.instanceof(TypeError);
      expect(error.message)
        .to.equal('The "publicKeyMultibase" property is required.');
    });
  });
});
