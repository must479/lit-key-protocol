import { ES256KSigner, JWTHeader, JWTPayload } from 'did-jwt'
import type {
  AuthParams,
  CreateJWSParams,
  DIDMethodName,
  DIDProviderMethods,
  DIDProvider,
  GeneralJWS,
} from 'dids'

import stringify from 'fast-json-stable-stringify'
import { RPCError, createHandler } from 'rpc-utils'
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc, RPCConnection } from 'rpc-utils'
import * as u8a from 'uint8arrays'
import elliptic from 'elliptic'
import { fromString } from 'uint8arrays/from-string'
// import { toString } from 'uint8arrays/to-string'
// import LitJsSdk from 'lit-js-sdk';
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

export interface JWSCreationOptions {
  canonicalize?: boolean
}
export async function createJWS(
  payload: string | Partial<JWTPayload>,
  signer: Signer,
  header: Partial<JWTHeader> = {},
): Promise<string> {

  console.log("PRIVATE KEY createJWS");
  if (!header.alg) header.alg = 'ES256K'
  const encodedPayload = typeof payload === 'string' ? payload : encodeSection(payload)
  const signingInput: string = [encodeSection(header), encodedPayload].join('.')

  const jwtSigner: SignerAlgorithm = SignerAlg(header.alg)
  const signature: string = await jwtSigner(signingInput, signer)

  console.log("JWS signature:", signature);

  const joined = [signingInput, signature].join('.');

  console.log("JWS joined:", joined);
  return joined
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

export function bytesToHex(b: Uint8Array): string {
  return u8a.toString(b, 'base16')
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return u8a.fromString(inputBase64Url, 'base64url')
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

export function toSealed(ciphertext: string, tag: string): Uint8Array {
  return u8a.concat([base64ToBytes(ciphertext), base64ToBytes(tag)])
}

export function leftpad(data: string, size = 64): string {
  if (data.length === size) return data
  return '0'.repeat(size - data.length) + data
}

const LitJsSdk = require('lit-js-sdk')
console.log(LitJsSdk);

const EC = elliptic.ec;
const ec = new EC('secp256k1')

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

export function encodeDID(publicKey: Uint8Array): string {

  console.log('[key-did-provider-secp256k1] encodeDID()');

  console.log("[encodeDIDWithLit] PUBLIC KEY:", publicKey);

  const bytes = new Uint8Array(publicKey.length + 2)
  bytes[0] = 0xe7 // secp256k1 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01
  bytes.set(publicKey, 2)
  return `did:key:z${u8a.toString(bytes, 'base58btc')}`
}



function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }],
  }
}

interface Context {
  did: string
  secretKey: Uint8Array
}
interface LitContext {
  did: string
}

const sign = async (
  payload: Record<string, any> | string,
  did: string,
  secretKey: Uint8Array,
  protectedHeader: Record<string, any> = {}
) => {

  console.log("[key-did-provider-secp256k1] sign:");
  console.log("payload:", payload);
  console.log("did:", did);
  console.log("secretKey:", secretKey);
  console.log("protectedHeader:", protectedHeader);

  const kid = `${did}#${did.split(':')[2]}`
  const signer = ES256KSigner(secretKey)

  console.log(signer);

  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256K' }))

  return createJWS(typeof payload === 'string' ? payload : toStableObject(payload), signer, header)
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
 export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number | null
}


export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  did_authenticate: async ({ did, secretKey }, params: AuthParams) => {
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did,
      secretKey
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ did, secretKey }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, did, secretKey, params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async () => {
    // Not implemented
    return { cleartext: '' }
  },
}

export class Secp256k1Provider implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>

  constructor(seed: Uint8Array) {
    const publicKey = ec.keyFromPrivate(seed).getPublic(true, 'array')    
    const did = encodeDID(Uint8Array.from(publicKey))

    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) => {
      console.log('[key-did-provider-secp256k1] msg', msg);
      
      const _handler = await handler({ did, secretKey:seed }, msg);
      return _handler;
    }
  }

  get isDidProvider(): boolean {
    return true
  }

  async send<Name extends DIDMethodName>(
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return await this._handle(msg)
  }
}

// --------------------------------------------------
// -                    WITH LIT                    -
// --------------------------------------------------

const litActionSignAndGetSignature = async (dataToSign: any) => {

  //  -- validate
  if(dataToSign == undefined ) throw Error('dataToSign cannot be empty')

  // -- prepare
  const DATA_TO_SIGN_IN_STRING = Array.from(fromString(dataToSign, 'utf8')).toString();
  
  const litCode = `
    const go = async () => {

        // this is the string "${dataToSign}" for testing
        const toSign = [${DATA_TO_SIGN_IN_STRING}];
        // this requests a signature share from the Lit Node
        // the signature share will be automatically returned in the HTTP response from the node
        const sigShare = await LitActions.signEcdsa({ toSign, keyId: 1, sigName: "sig1" });
    };

    go();
  `;

  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });

  await litNodeClient.connect();

  const signatures = await litNodeClient.executeJs({
    code: litCode,
    authSig,
  });

  return signatures;
}



export function hexToBytes(s: string): Uint8Array {
  const input = s.startsWith('0x') ? s.substring(2) : s
  return u8a.fromString(input.toLowerCase(), 'base16')
}

// function extractPublicKeyBytes(pk: any): Uint8Array {
//   return hexToBytes(
//     ec
//       .keyFromPublic({
//         x: bytesToHex(base64ToBytes(pk.publicKeyJwk.x)),
//         y: bytesToHex(base64ToBytes(pk.publicKeyJwk.y)),
//       })
//       .getPublic('hex')
//   )
// }

export async function encodeDIDWithLit(): Promise<string> {

  console.log('[key-did-provider-secp256k1] encodeDIDWithLit()');

  const signatures = (await litActionSignAndGetSignature('0'));

  const PKP_PUBLIC_KEY = signatures.sig1.publicKey;

  console.log("[encodeDIDWithLit] PKP_PUBLIC_KEY:", PKP_PUBLIC_KEY);

  const pubBytes = ec
  .keyFromPublic(PKP_PUBLIC_KEY, 'hex')
  .getPublic(true, 'array');

  console.log("[encodeDIDWithLit] pubBytes:", pubBytes)

  const bytes = new Uint8Array(pubBytes.length + 2);
  bytes[0] = 0xe7
  bytes[1] = 0x01
  bytes.set(pubBytes, 2)
  console.log("[encodeDIDWithLit] bytes:", bytes)

  const did = `did:key:z${u8a.toString(bytes, 'base58btc')}`;
  console.log("[encodeDIDWithLit] did:", did)

  return did;

}

// TODO: THIS should be able to verify
// return secp256k1.keyFromPublic(pubBytes).verify(hash6, sigObj);

// Forked version of EllpiticSign using LitAction
// 
// It uses the ellpitic curve used in Bitcoin and Ethereum (secp256k1), also known as "The Bitcoin curve",
// as defined in the Standards for Efficient Cryptography (SEC1)
// https://www.cem.me/art/cryptoposters/secp256k1.png
// @return { Function } signer 
// 
export function ellipticSignerWithLit() : Signer {

  console.log("[Function Called] ellipticSignerWithLit()");

  // 
  // Return a signer function
  // @param { String } dataToSign
  // @return { Uint8Array } signature from lit node
  // 
  return async (dataToSign: string | Uint8Array): Promise<string> => {

    // -- validate
    if(dataToSign == undefined) throw new Error('dataToSign');

    // -- prepare
    const signatures = await litActionSignAndGetSignature(dataToSign);
    console.log("signatures:", signatures)

    
    const ecdsaSignature = toJose(
      {
        r: leftpad(signatures.sig1.r.toString('hex')),
        s: leftpad(signatures.sig1.s.toString('hex')),
        recoveryParam: signatures.sig1.recid,
      },
      false
    )

    console.log("ecdsaSignature:", ecdsaSignature);

    return ecdsaSignature

  }
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function encodeBase64url(s: string): string {
  return bytesToBase64url(u8a.fromString(s))
}


function encodeSection(data: any): string {
  return encodeBase64url(JSON.stringify(data))
}

interface SignerAlgorithms {
  [alg: string]: SignerAlgorithm
}

function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
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

const algorithms: SignerAlgorithms = {
  ES256K: ES256KSignerAlg(),
}

function SignerAlg(alg: string): SignerAlgorithm {
  const impl: SignerAlgorithm = algorithms[alg]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}

export async function createJWS2(
  payload: string | Partial<JWTPayload>,
  signer: Signer,
  header: Partial<JWTHeader> = {}
): Promise<string> {

  console.log("LIT: createJWS2");
  if (!header.alg) header.alg = 'ES256K'
  
  const encodedPayload = typeof payload === 'string' ? payload : encodeSection(payload)
  
  const signingInput: string = [encodeSection(header), encodedPayload].join('.')

  const jwtSigner: SignerAlgorithm = SignerAlg(header.alg)
  
  const signature: string = await jwtSigner(signingInput, signer)

  console.log("createJWS2 signature:", signature);
  
  const joined = [signingInput, signature].join('.');
  
  console.log("joined:", joined);
  
  return joined
}

const signWithLit = async (
  payload: Record<string, any> | string,
  did: string,
  // secretKey: Uint8Array,
  protectedHeader: Record<string, any> = {}
) => {

  console.log("[key-did-provider-secp256k1] signWithLit:");

  const kid = `${did}#${did.split(':')[2]}`
  const signer = ellipticSignerWithLit();

  console.log("[signWithLixt] signer:", signer);
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256K' }))
  console.log("header:", header)
  const jws = createJWS2(typeof payload === 'string' ? payload : toStableObject(payload), signer, header);
  
  const test = await jws;

  console.warn("signWithLit test:", test);

  return jws;
}

export declare type DIDProviderMethodsWithLit = {
  did_authenticate: {
      params: AuthParams;
      result: GeneralJWS;
  };
  // did_createJWS: {
  //     params: CreateJWSParams;
  //     result: {
  //         jws: GeneralJWS;
  //     };
  // };
  // did_decryptJWE: {
  //     params: DecryptJWEParams;
  //     result: {
  //         cleartext: string;
  //     };
  // };
};

const didMethodsWithLit: HandlerMethods<LitContext, DIDProviderMethodsWithLit> = {
  did_authenticate: async ({ did }, params: AuthParams) => {
    const response = await signWithLit(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did
    )

    console.log("didMethodsWithLit response:", response);
    
    const general = toGeneralJWS(response);

    console.log("didMethodsWithLit general:", general);

    return general;
  },
  // did_createJWS: async ({ did, secretKey }, params: CreateJWSParams & { did: string }) => {
  //   const requestDid = params.did.split('#')[0]
  //   if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
  //   const jws = await sign(params.payload, did, secretKey, params.protected)
  //   return { jws: toGeneralJWS(jws) }
  // },
  // did_decryptJWE: async () => {
  //   // Not implemented
  //   return { cleartext: '' }
  // },
}

export declare type DIDMethodNameWithLit = keyof DIDProviderMethodsWithLit;

export declare type DIDProviderWithLit = RPCConnection<DIDProviderMethodsWithLit>;

// 
// Lit version of Secp256k1Provider without private key
// 
export class Secp256k1ProviderWithLit implements DIDProviderWithLit {
  _handle: SendRequestFunc<DIDProviderMethodsWithLit>

  constructor(did: string) {

    console.log('[key-did-provider-secp256k1] Class::Secp256k1ProviderWithLit');
    
    const handler = createHandler<LitContext, DIDProviderMethodsWithLit>(didMethodsWithLit)
    this._handle = async (msg) => {
      console.log('[key-did-provider-secp256k1] msg', msg);
      const _handler = await handler({ did }, msg); 
      return _handler;
    }
  }

  get isDidProvider(): boolean {
    return true
  }

  async send<Name extends DIDMethodNameWithLit>(
    msg: RPCRequest<DIDProviderMethodsWithLit, Name>
  ): Promise<RPCResponse<DIDProviderMethodsWithLit, Name> | null> {
    return await this._handle(msg)
  }
}
