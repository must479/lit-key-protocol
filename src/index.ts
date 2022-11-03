import { Signer, createJWS } from "did-jwt";
import type { AuthParams, CreateJWSParams } from "dids";
import type {
  HandlerMethods,
  RPCRequest,
  RPCResponse,
  SendRequestFunc,
} from "rpc-utils";
import { RPCError, createHandler } from "rpc-utils";
import * as u8a from "uint8arrays";
import elliptic from "elliptic";
import LitJsSdk from "lit-js-sdk";
import { toGeneralJWS, toJose, toStableObject, sha256, log } from "./util.js";
import {
  ContextWithLit,
  DIDMethodNameWithLit,
  DIDProviderMethodsWithLit,
  DIDProviderWithLit,
  EcdsaSignature
} from "./interfaces.js";

const ec = new elliptic.ec("secp256k1");

/**
 *
 * Execute the Lit Action code and return a signature
 *
 * @param { Uint8Array } sha256Payload a payload that is hashed using sha256() function
 * @param { ContextWithLit } context
 * (eg. https://ipfs.io/ipfs/QmQf55oeY5AXgHToWz3kZD8qQKzNv25fEdzyp5dNrYRUPj)
 *
 * @example
 * ```
 * const signature = await litActionSignAndGetSignature(
 *   sha256(payload),
 *   "QmQf55oeY5AXgHToWz3kZD8qQKzNv25fEdzyp5dNrYRUPj"
 * )
 * ```
 *
 * @returns { EcdsaSignature } signature
 *
 */
export const litActionSignAndGetSignature = async (
  sha256Payload: Uint8Array,
  context: ContextWithLit
): Promise<EcdsaSignature> => {

  log("[litActionSignAndGetSignature] sha256Payload: ", sha256Payload);

  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  log("[litActionSignAndGetSignature] authSig:", authSig);

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });

  await litNodeClient.connect();

  log("[litActionSignAndGetSignature] ipfsId:", context.ipfsId);

  const jsParams = {
    toSign: Array.from(sha256Payload),
    keyId: decodeDIDWithLit(context.did),
    sigName: "sig1",
  };

  log("[litActionSignAndGetSignature] jsParams:", jsParams);

  const executeOptions = {
    ...(context.ipfsId === undefined || ! context.ipfsId) && {code: context.litCode},
    ...(context.litCode === undefined || ! context.litCode) && {ipfsId: context.ipfsId},
    authSig,
    jsParams,
  }

  const res = await litNodeClient.executeJs(executeOptions);

  log("[litActionSignAndGetSignature] res.signatures:", res.signatures);

  const signature = res.signatures;

  return {
    r: signature.sig1.r,
    s: signature.sig1.s,
    recoveryParam: signature.sig1.recid,
  };
};

/**
 * Create a DID (decentralized identifier) by using the PKP public key
 *
 * @example
 * ```typescript
 * // -- get the DID (eg. did:key:xxxx )
 * const encodedDID = await encodeDIDWithLit();
 * ```
 * @param { string } pkpPublicKey
 * @returns {String} did a decentralised identifier
 */
export async function encodeDIDWithLit(
  PKP_PUBLIC_KEY: string
): Promise<string> {
  // -- prepare

  const pkpPubKey = PKP_PUBLIC_KEY.replace('0x', '')

  log("[encodeDIDWithLit] pkpPubKey:", pkpPubKey);

  const pubBytes = ec
    .keyFromPublic(pkpPubKey, "hex")
    .getPublic(true, "array");

  log("[encodeDIDWithLit] pubBytes:", pubBytes);

  // https://github.com/multiformats/multicodec/blob/master/table.csv
  const bytes = new Uint8Array(pubBytes.length + 2);
  bytes[0] = 0xe7; // <-- 0xe7 is a Secp256k1 public key (compressed)
  bytes[1] = 0x01; // <-- 0x01 is a content identifier cidv1
  bytes.set(pubBytes, 2);
  log("[encodeDIDWithLit] bytes:", bytes);

  const did = `did:key:z${u8a.toString(bytes, "base58btc")}`;
  log(`[encodeDIDWithLit] did:`, did);

  return did;
}

/**
 * 
 * Decode encodedDID and return the PKP public key in a uncompressed form
 * 
 * @param encodedDID 
 * @returns { string } PKP Public Key in uncompressed form
 */
export function decodeDIDWithLit(
  encodedDID: string
): string {

    log("[decodeDIDWithLit] encodedDID:", encodedDID);

    // -- validate
    const arr = encodedDID?.split(':');

    if(arr[0] != 'did') throw Error('string should start with did:');
    if(arr[1] != 'key') throw Error('string should start with did:key');
    if(arr[2].charAt(0) !== 'z') throw Error('string should start with did:key:z');

    const str = arr[2].substring(1);;

    log("[decodeDIDWithLit] str:", str);

    const bytes = u8a.fromString(str, "base58btc");

    const originalBytes = new Uint8Array(bytes.length - 2);

    bytes.forEach((_, i) => {
        originalBytes[i] = bytes[i + 2];
    });
    
    log("[decodeDIDWithLit] originalBytes:", originalBytes);

    const pubPoint = ec.keyFromPublic(originalBytes).getPublic();
    
    let pubKey = pubPoint.encode('hex', false);

    pubKey = pubKey.charAt(0) == '0' ? pubKey.substring(1) : pubKey;

    log("[decodeDIDWithLit] pubKey:", pubKey);
    
    return '0x0' + pubKey;
}

/**
 *
 * Creates a configured signer function for signing data using the ES256K (secp256k1 + sha256) algorithm.
 * The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 * @param { ContextWithLit } context
 *
 * @return {Function} a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSignerWithLit(context: ContextWithLit): Signer {
  log("[ES256KSignerWithLit]");

  const recoverable = false;

  return async (payload: string | Uint8Array): Promise<string> => {
    const encryptedPayload = sha256(payload);

    log("[ES256KSignerWithLit] encryptedPayload:", encryptedPayload);

    const signature = await litActionSignAndGetSignature(
      encryptedPayload,
      context
    );

    log("[ES256KSignerWithLit] signature:", signature);

    return toJose(signature, recoverable);
  };
}

/**
 *
 * Signing with Lit Actions which is signed by the lit nodes
 *
 * @param payload
 * @param { Record<string, any> | string } payload
 * @param { ContextWithLit } context
 *
 * @returns {Promise<string>} a JWS string
 *
 */
const signWithLit = async (
  payload: Record<string, any> | string,
  context: ContextWithLit
): Promise<string> => {
  const did = context.did;

  log("[signWithLit] did:", did);

  const kid = `${did}#${did.split(":")[2]}`;

  log("[signWithLit] kid:", kid);

  const protectedHeader: Record<string, any> = {};

  const header = toStableObject(
    Object.assign(protectedHeader, { kid, alg: "ES256K" })
  );

  log("[signWithLit] header:", header);

  log("[signWithLit] payload:", payload);

  return createJWS(
    typeof payload === "string" ? payload : toStableObject(payload),
    ES256KSignerWithLit(context),
    header
  );
};

/**
 * Define DID methods that matches the "DIDProviderMethodsWithLit" type
 */
const didMethodsWithLit: HandlerMethods<
  ContextWithLit,
  DIDProviderMethodsWithLit
> = {
  did_authenticate: async (
    contextParam: ContextWithLit,
    params: AuthParams
  ) => {
    const payload = {
      did: contextParam.did,
      aud: params.aud,
      nonce: params.nonce,
      paths: params.paths,
      exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
    };

    log("[didMethodsWithLit] payload:", payload);

    const response = await signWithLit(payload, contextParam);

    log("[didMethodsWithLit] response:", response);

    const general = toGeneralJWS(response);

    log("[didMethodsWithLit] general:", general);

    return general;
  },
  did_createJWS: async (
    contextParam: ContextWithLit,
    params: CreateJWSParams & { did: string }
  ) => {
    const requestDid = params.did.split("#")[0];
    if (requestDid !== contextParam.did)
      throw new RPCError(4100, `Unknown DID: ${contextParam.did}`);
    const jws = await signWithLit(params.payload, contextParam);

    log("[did_createJWS] jws:", jws);

    return { jws: toGeneralJWS(jws) };
  },
  did_decryptJWE: async () => {
    // Not implemented
    return { cleartext: "" };
  },
};

/**
 * secp256k1 provider using Lit Actions instead of passing in a private key
 */
export class Secp256k1ProviderWithLit implements DIDProviderWithLit {
  _handle: SendRequestFunc<DIDProviderMethodsWithLit>;

  constructor(context: ContextWithLit) {
    const handler = createHandler<ContextWithLit, DIDProviderMethodsWithLit>(
      didMethodsWithLit
    );

    this._handle = async (msg) => {
      log("[Secp256k1ProviderWithLit] this._handle(msg):", msg);

      const _handler = await handler(context, msg);

      return _handler;
    };
  }

  get isDidProvider(): boolean {
    return true;
  }

  async send<Name extends DIDMethodNameWithLit>(
    msg: RPCRequest<DIDProviderMethodsWithLit, Name>
  ): Promise<RPCResponse<DIDProviderMethodsWithLit, Name> | null> {
    return await this._handle(msg);
  }
}
