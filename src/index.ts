import { 
  JWTHeader, 
  JWTPayload,
  ES256KSigner,
  Signer,

  createJWS
} from 'did-jwt'

import type {
  AuthParams,
  CreateJWSParams,
  DIDMethodName,
  DIDProviderMethods,
  DIDProvider,
  GeneralJWS,
  DecryptJWEParams,
} from 'dids'

import { 
  encodeSection, 
  SignerAlg, 
  SignerAlgorithm, 
  toGeneralJWS, 
  toJose, 
  toStableObject 
} from './util'

import type { 
  HandlerMethods, 
  RPCRequest, 
  RPCResponse, 
  SendRequestFunc, 
  RPCConnection 
} from 'rpc-utils'

import {
  RPCError, 
  createHandler 
} from 'rpc-utils'

import * as u8a from 'uint8arrays'
import elliptic from 'elliptic'
import { sha256 } from './util'

const LitJsSdk = require('lit-js-sdk')
console.log(LitJsSdk);

const EC = elliptic.ec;
const ec = new EC('secp256k1')

interface Context {
  did: string
  secretKey: Uint8Array
}

export function encodeDID(publicKey: Uint8Array): string {

  console.log('[key-did-provider-secp256k1] encodeDID()');

  console.log("[encodeDID] PUBLIC KEY:", publicKey);

  const bytes = new Uint8Array(publicKey.length + 2)
  bytes[0] = 0xe7 // secp256k1 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01
  bytes.set(publicKey, 2)
  return `did:key:z${u8a.toString(bytes, 'base58btc')}`
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
      console.log('[key-did-provider-secp256k1] msg THIS', msg);
      
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

const getPKPPublicKey = async () => {

  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });
  
  await litNodeClient.connect();

  const signatures = await litNodeClient.executeJs({
    code: `
      const go = async () => {
        const toSign = [];
        const sigShare = await LitActions.signEcdsa({ toSign, keyId: 1, sigName: "sig1" });
      };
      go();
    `,
    authSig,
  });

  return signatures.sig1.publicKey;

}

const litActionSignAndGetSignature = async (dataToSign: Uint8Array, param: Secp256k1ProviderWithLitContext) => {


  console.log("litActionSignAndGetSignature:", dataToSign);

  //  -- validate
  if(dataToSign == undefined ) throw Error('dataToSign cannot be empty')

  // -- prepare
  // const DATA_TO_SIGN_IN_STRING = Array.from(dataToSign).toString();
  
  const litCode = param.litCode(dataToSign);

  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });

  await litNodeClient.connect();

  const signatures = await litNodeClient.executeJs({
    code: litCode,
    authSig,
  });

  return signatures;
}

export async function encodeDIDWithLit(): Promise<string> {

  console.log('[key-did-provider-secp256k1] encodeDIDWithLit()');

  const PKP_PUBLIC_KEY = await getPKPPublicKey();

  console.log("[encodeDIDWithLit] PKP_PUBLIC_KEY:", PKP_PUBLIC_KEY);

  const pubBytes = ec.keyFromPublic(PKP_PUBLIC_KEY, 'hex').getPublic(true, 'array');

  console.log("[encodeDIDWithLit] pubBytes:", pubBytes)

  // https://github.com/multiformats/multicodec/blob/master/table.csv
  const bytes = new Uint8Array(pubBytes.length + 2);
  bytes[0] = 0xe7 // <-- 0xe7 is a Secp256k1 public key (compressed)
  bytes[1] = 0x01 // <-- 0x01 is a content identifier cidv1
  bytes.set(pubBytes, 2)
  console.log("[encodeDIDWithLit] bytes:", bytes)

  const did = `did:key:z${u8a.toString(bytes, 'base58btc')}`;
  console.log(`%c[encodeDIDWithLit] did: "${did}"`, "color: #FF79C6")

  return did;

}

export function ES256KSignerWithLit(param: Secp256k1ProviderWithLitContext): Signer {

  const recoverable = false;

  return async (data: string | Uint8Array): Promise<string> => {

    console.warn("ES256KSignerWithLit", sha256(data));

    const singature = (await litActionSignAndGetSignature(sha256(data), param)).sig1;
    
    // const { r, s, recoveryParam }: elliptic.ec.Signature = keyPair.sign(sha256(data))
    return toJose(
      {
        r: singature.r,
        s: singature.s,
        recoveryParam: singature.recid,
      },
      recoverable
    )
  }
}


export async function createJWSWithLit(
  payload: string | Partial<JWTPayload>,
  signer: Signer,
  header: Partial<JWTHeader> = {}
): Promise<string> {

  console.log("LIT: createJWSWithLit");
  if (!header.alg) header.alg = 'ES256K'
  
  const encodedPayload = typeof payload === 'string' ? payload : encodeSection(payload)
  
  const signingInput: string = [encodeSection(header), encodedPayload].join('.')

  const jwtSigner: SignerAlgorithm = SignerAlg(header.alg)
  
  const signature: string = await jwtSigner(signingInput, signer)

  console.log("createJWSWithLit signature:", signature);
  
  const JWS = [signingInput, signature].join('.');
  
  console.log(`%cJWS:${JWS}`, 'color: #FF79C6');
  
  return JWS
}

export declare type DIDProviderMethodsWithLit = {
  did_authenticate: {
      params: AuthParams;
      result: GeneralJWS;
  };
  did_createJWS: {
      params: CreateJWSParams;
      result: {
          jws: GeneralJWS;
      };
  };
  did_decryptJWE: {
      params: DecryptJWEParams;
      result: {
          cleartext: string;
      };
  };
};


const signWithLit = async (
  payload: Record<string, any> | string,
  param: Secp256k1ProviderWithLitContext,
  protectedHeader: Record<string, any> = {}
) => {

  console.log("[key-did-provider-secp256k1] signWithLit:");

  const kid = `${param.did}#${param.did.split(':')[2]}`
  
  const signer = ES256KSignerWithLit(param);

  console.log("[signWithLixt] signer:", signer);
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256K' }))
  console.log("header:", header)

  return createJWSWithLit(typeof payload === 'string' ? payload : toStableObject(payload), signer, header);
}

const didMethodsWithLit: HandlerMethods<Secp256k1ProviderWithLitContext, DIDProviderMethodsWithLit> = {
  did_authenticate: async ({ did, litCode }, params: AuthParams) => {
    const response = await signWithLit(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      {
        did,
        litCode
      }
    )

    console.log("didMethodsWithLit response:", response);
    
    const general = toGeneralJWS(response);

    console.log("didMethodsWithLit general:", general);

    return general;
  },
  did_createJWS: async ({ did, litCode }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await signWithLit(params.payload, {
      did,
      litCode
    }, params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async () => {
    // Not implemented
    return { cleartext: '' }
  },
}

export declare type DIDMethodNameWithLit = keyof DIDProviderMethodsWithLit;

export declare type DIDProviderWithLit = RPCConnection<DIDProviderMethodsWithLit>;

interface Secp256k1ProviderWithLitContext {
  did: string
  litCode: Function
}

// 
// Lit version of Secp256k1Provider without private key
// 
export class Secp256k1ProviderWithLit implements DIDProviderWithLit {
  _handle: SendRequestFunc<DIDProviderMethodsWithLit>

  constructor(param: Secp256k1ProviderWithLitContext) {

    console.log('[key-did-provider-secp256k1] Class::Secp256k1ProviderWithLit');
    
    const handler = createHandler<Secp256k1ProviderWithLitContext, DIDProviderMethodsWithLit>(didMethodsWithLit)
    this._handle = async (msg) => {
      console.log('[key-did-provider-secp256k1] msg THIS2', msg);
      const _handler = await handler(param, msg); 
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
