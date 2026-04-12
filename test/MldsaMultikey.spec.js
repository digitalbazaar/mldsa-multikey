/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
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
    it('deriveSecret() should not be supported by default', async () => {
      const keyPair = await MldsaMultikey.generate({nistSecurityLevel: 2});

      let err;
      try {
        await keyPair.deriveSecret({publicKey: keyPair});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotSupportedError');
    });

    it.skip('deriveSecret() should produce a shared secret', async () => {
      const keyPair1 = await MldsaMultikey.generate(
        {nistSecurityLevel: 2, keyAgreement: true});
      const keyPair2 = await MldsaMultikey.generate(
        {nistSecurityLevel: 2, keyAgreement: true});

      const secret1 = await keyPair1.deriveSecret({publicKey: keyPair2});
      const secret2 = await keyPair2.deriveSecret({publicKey: keyPair1});

      expect(secret1).to.deep.eql(secret2);
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
