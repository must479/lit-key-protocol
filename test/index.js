import { encodeDIDWithLit, Secp256k1ProviderWithLit } from '../dist/index.js';
import { assert } from "console";
import { expect } from 'chai';

describe('encodeDIDWithLit', () => {

    const PKP_PUBLIC_KEY = '30eceb963993d467ca197f3fd9fe3073b8b224ac2c9068d9a9caafcd5e20cf983';

    it('should be a string', async function () {

        const encodedDID = await encodeDIDWithLit({
            pkpPublicKey: PKP_PUBLIC_KEY
        });

        expect(encodedDID).to.be.a.string;
    });

    it('should have prefix "did:key:"', async function () {

        const encodedDID = await encodeDIDWithLit({
            pkpPublicKey: PKP_PUBLIC_KEY
        });

        const arr = encodedDID.split(':');

        expect(arr).to.include.members(['key', 'did'])
    });

    it('should return "did:key:zQ3shfdufQXuqrY4TYSGuk2W7VdDUzzFTSnTWSLA1FhmhdMce" with this public key "30eceb963993d467ca197f3fd9fe3073b8b224ac2c9068d9a9caafcd5e20cf983"', async () => {
        const encodedDID = await encodeDIDWithLit({
            pkpPublicKey: PKP_PUBLIC_KEY
        });

        expect(encodedDID).to.equal('did:key:zQ3shfdufQXuqrY4TYSGuk2W7VdDUzzFTSnTWSLA1FhmhdMce');
    })
})

// describe('Secp256k1ProviderWithLit', () => {
    
// });