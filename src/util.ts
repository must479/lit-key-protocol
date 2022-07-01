import * as u8a from 'uint8arrays'
import { 
    Signer,
    base64ToBytes,
  } from 'did-jwt'

import type {
    GeneralJWS,
} from 'dids'

import stringify from 'fast-json-stable-stringify'

import { hash } from '@stablelib/sha256'

export function sha256(payload: string | Uint8Array): Uint8Array {
  const data = typeof payload === 'string' ? u8a.fromString(payload) : payload
  return hash(data)
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
export interface EcdsaSignature {
    r: string
    s: string
    recoveryParam?: number | null
}

export interface JWSCreationOptions {
    canonicalize?: boolean
}

export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>


export interface SignerAlgorithms {
    [alg: string]: SignerAlgorithm
}
export function bytesToBase64url(b: Uint8Array): string {
    return u8a.toString(b, 'base64url')
}

export function encodeBase64url(s: string): string {
    return bytesToBase64url(u8a.fromString(s))
}

export function encodeSection(data: any): string {
    return encodeBase64url(JSON.stringify(data))
}

export function bytesToHex(b: Uint8Array): string {
    return u8a.toString(b, 'base16')
}

export function toStableObject(obj: Record<string, any>): Record<string, any> {
    return JSON.parse(stringify(obj)) as Record<string, any>
}

export function toGeneralJWS(jws: string): GeneralJWS {
    const [protectedHeader, payload, signature] = jws.split('.')
    return {
        payload,
        signatures: [{ protected: protectedHeader, signature }],
    }
}
  
export function toJose({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string {
    const jose = new Uint8Array(recoverable ? 65 : 64)
    jose.set(u8a.fromString(r, 'base16'), 0)
    jose.set(u8a.fromString(s, 'base16'), 32)
    if (recoverable) {
        if (typeof recoveryParam === 'undefined') {
        throw new Error('Signer did not return a recoveryParam')
        }
        jose[64] = <number>recoveryParam
    }
    return bytesToBase64url(jose)
}

export function fromJose(signature: string): { r: string; s: string; recoveryParam?: number } {
    const signatureBytes: Uint8Array = base64ToBytes(signature)
    if (signatureBytes.length < 64 || signatureBytes.length > 65) {
        throw new TypeError(`Wrong size for signature. Expected 64 or 65 bytes, but got ${signatureBytes.length}`)
    }
    const r = bytesToHex(signatureBytes.slice(0, 32))
    const s = bytesToHex(signatureBytes.slice(32, 64))
    const recoveryParam = signatureBytes.length === 65 ? signatureBytes[64] : undefined
    return { r, s, recoveryParam }
}

export function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
    return typeof object === 'object' && 'r' in object && 's' in object
}

export function ES256KSignerAlg(recoverable?: boolean): SignerAlgorithm {
    return async function sign(payload: string, signer: Signer): Promise<string> {
        const signature: EcdsaSignature | string = await signer(payload)
        if (instanceOfEcdsaSignature(signature)) {
        return toJose(signature, recoverable)
        } else {
        if (recoverable && typeof fromJose(signature).recoveryParam === 'undefined') {
            throw new Error(`not_supported: ES256K-R not supported when signer doesn't provide a recovery param`)
        }
        return signature
        }
    }
}
  
export const algorithms: SignerAlgorithms = {
    ES256K: ES256KSignerAlg(),
}

export function SignerAlg(alg: string): SignerAlgorithm {
    const impl: SignerAlgorithm = algorithms[alg]
    if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
    return impl
}

const getInstanceType = (value: any) => {
    if(value instanceof Object){
        if(value.constructor.name == 'Object'){
            return 'Object';
        }
        return value.constructor.name;
    }
    return typeof value;
}

export function log(name: string, value: any, printObj: boolean = false){
    
    const instanceType = getInstanceType(value);

    let text : string;

    try{
        text = JSON.stringify(value);
    }catch(e){
        text = '';
    }

    if( printObj == false){
        console.log(`%c[key-did-provider-secp256k1]: ${name}${instanceType != null ? `(${instanceType})` : ''} "${text}"`, "color: #FF79C6");
        return;
    }

    console.log(`%c[key-did-provider-secp256k1]: ${name}${instanceType != null ? `(${instanceType})` : ''}`, "color: #FF79C6");

    console.log(value);

}