import { createJWS, ES256KSigner } from 'did-jwt'
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
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc } from 'rpc-utils'
import * as u8a from 'uint8arrays'
import elliptic from 'elliptic'
const EC = elliptic.ec;
const ec = new EC('secp256k1')

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

export function encodeDID(publicKey: Uint8Array): string {
  const bytes = new Uint8Array(publicKey.length + 2)
  bytes[0] = 0xe7 // secp256k1 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01
  bytes.set(publicKey, 2)
  return `did:key:z${u8a.toString(bytes, 'base58btc')}`
}

export function encodeDIDWithLit(publicKey: string): string {

  console.log('[key-did-provider-secp256k1] encodeDIDWithLit()');

  const pubBytes = ec
  .keyFromPublic(publicKey, 'hex')
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
  const kid = `${did}#${did.split(':')[2]}`
  const signer = ES256KSigner(secretKey)
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
    this._handle = async (msg) => await handler({ did, secretKey:seed }, msg)
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

export class Secp256k1ProviderWithLit implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>

  constructor(did: string) {

    console.log('[key-did-provider-secp256k1] Class::Secp256k1ProviderWithLit');

    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) => await handler({ did: did, secretKey: new Uint8Array() }, msg)
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
