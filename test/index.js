import { encodeDIDWithLit } from '../dist/index.js';
import { assert } from "console";
import { expect } from 'chai';

describe('test', () => {

    const PKP_PUBLIC_KEY = '30eceb963993d467ca197f3fd9fe3073b8b224ac2c9068d9a9caafcd5e20cf983';

    it('encodedDID should be a string', async function () {

        const encodedDID = await encodeDIDWithLit({
            pkpPublicKey: PKP_PUBLIC_KEY
        });

        expect(encodedDID).to.be.a.string;
    });

    it('encodedDID should have prefix "did:key:"', async function () {

        const encodedDID = await encodeDIDWithLit({
            pkpPublicKey: PKP_PUBLIC_KEY
        });

        const arr = encodedDID.split(':');

        console.log(arr);

        expect(arr).to.include.members(['key', 'did'])
    });
})