import { Signer, createJWS } from "did-jwt";
import type { AuthParams, CreateJWSParams } from "dids";
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc } from "rpc-utils";
import { RPCError, createHandler } from "rpc-utils";
import * as u8a from "uint8arrays";
import elliptic from "elliptic";
import LitJsSdk from "lit-js-sdk";
import { toGeneralJWS, toJose, toStableObject, sha256, log } from "./util.js";
import { ContextWithLit, DIDMethodNameWithLit, DIDProviderMethodsWithLit, DIDProviderWithLit, IPFSData } from "./interfaces.js";
import * as IPFS from 'ipfs-core'

const ec = new elliptic.ec("secp256k1");

// TODO: we need to make it possible to pass a public key to use as well
// - Hot it works right now (https://github.com/LIT-Protocol/js-serverless-function-test/blob/main/js-sdkTests/litConditions.js#L61)
// - Anything you pass in to jsParams will be exposed globally to your lit action\
// - Instead of using string interpolation to generate the JS code each time, the JS code can be static.
// - The JS code can be uploaded to IPFS and then you can just specify the IPFS id in Secp256k1ProviderWithLit instead of creating the code each time


/**
 * 
 * Upload code to IPFS
 * 
 * @param { string } code
 * @returns 
 */
export async function uploadToIPFS(code: string) : Promise<IPFSData> {

  log("[uploadToIPFS] param: ", code);

  const ipfs = await IPFS.create()

  const { path } = await ipfs.add(code)

  const data : IPFSData = {
    path: path,
    url: `https://ipfs.io/ipfs/${path}`,
  };

  log("[uploadToIPFS] data: ", data);

  return data

}

/**
 * Fetch the IPFS content and return as text
 * @param { string } ipfsPath IPFS path  
 * @returns { string } text
 */
export async function ipfsFetch(ipfsPath: string) {
  
  log("[ipfsFetch]: ", ipfsPath);

  const res = await fetch(`https://ipfs.io/ipfs/${ipfsPath}`);

  const data = await res.text();

  log("[ipfsFetch] data:", data);

  return data;

}

/**
 * 
 * Get the PKP public key
 * 
 * @returns { String } public key
 */
const getPKPPublicKey = async () => {
  return '30eceb963993d467ca197f3fd9fe3073b8b224ac2c9068d9a9caafcd5e20cf983';
};

/**
 * 
 * Sign and get signature with Lit Action
 * 
 * @param sha256Payload 
 * @returns { Object } signatures
 */
export const litActionSignAndGetSignature = async (sha256Payload: Uint8Array, ipfsId: string) => {

  log("[litActionSignAndGetSignature]:", sha256Payload);

  //  -- validate
  if (sha256Payload == undefined) throw Error("sha256Payload cannot be empty");

  const codeToVerifyES256K = `
    const go = async () => {

        // this is the string "${sha256Payload}" for testing
        const toSign = [${Array.from(sha256Payload).toString()}];
        // this requests a signature share from the Lit Node
        // the signature share will be automatically returned in the HTTP response from the node
        const sigShare = await LitActions.signEcdsa({ toSign, keyId: 1, sigName: "sig1" });
    };

    go();
  `;

  log("[litActionSignAndGetSignature] ipfsId:", ipfsId)

  const codeToRun = await ipfsFetch(ipfsId);

  log("codeToRun:", codeToRun);
  
  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });

  await litNodeClient.connect();

  const ES256kVerifySignature = await litNodeClient.executeJs({
    code: codeToVerifyES256K,
    authSig,
  });

  const litActionSignature = await litNodeClient.executeJs({
    code: codeToRun,
    authSig,
  })

  console.log("litActionSignature:", litActionSignature);

  return {
    ES256kVerifySignature: ES256kVerifySignature.sig1,
    litActionSignature: litActionSignature.sig1
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
 * 
 * @returns {String} did a decentralised identifier
 */
export async function encodeDIDWithLit(): Promise<string> {

  const PKP_PUBLIC_KEY = await getPKPPublicKey();

  log("[encodeDIDWithLit] PKP_PUBLIC_KEY:", PKP_PUBLIC_KEY);

  const pubBytes = ec
    .keyFromPublic(PKP_PUBLIC_KEY, "hex")
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
 *  Creates a configured signer function for signing data using the ES256K (secp256k1 + sha256) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSignerWithLit(ipfsId: string): Signer {

  log("[ES256KSignerWithLit]");

  const recoverable = false;

  return async (payload: string | Uint8Array): Promise<string> => {
    
    const encryptedPayload = sha256(payload)
    
    log("[ES256KSignerWithLit] encryptedPayload:",encryptedPayload);

    const { ES256kVerifySignature, litActionSignature } = await litActionSignAndGetSignature(encryptedPayload, ipfsId)

    log("[ES256KSignerWithLit] ES256kVerifySignature:", ES256kVerifySignature)
    log("[ES256KSignerWithLit] litActionSignature:", litActionSignature)

    return toJose(
      {
        r: litActionSignature.r,
        s: litActionSignature.s,
        recoveryParam: litActionSignature.recid,
      },
      recoverable
    );
  };
}


/**
 * 
 * Signing with Lit Actions which is signed by the lit nodes
 * 
 * @param payload 
 * @param did 
 * @param protectedHeader 
 * 
 * @returns {Promise<string>} a JWS string
 * 
 */
const signWithLit = async (
  payload: Record<string, any> | string,
  contextParam: ContextWithLit,
  protectedHeader: Record<string, any> = {}
) => {

  const did = contextParam.did;

  log("[signWithLit] did:", did);

  const kid = `${did}#${did.split(":")[2]}`;

  log("[signWithLit] kid:", kid);

  const header = toStableObject(
    Object.assign(protectedHeader, { kid, alg: "ES256K" })
  );

  log("[signWithLit] header:", header);

  log("[signWithLit] payload:", payload);

  return createJWS(
    typeof payload === "string" ? payload : toStableObject(payload),
    ES256KSignerWithLit(contextParam.ipfsId),
    header
  );
};


/**
 * Define DID methods that matches the "DIDProviderMethodsWithLit" type
 */
const didMethodsWithLit: HandlerMethods<ContextWithLit, DIDProviderMethodsWithLit> = {
  did_authenticate: async (contextParam: ContextWithLit, params: AuthParams) => {

    const payload = {
      did: contextParam.did,
      aud: params.aud,
      // nonce: "uSFvD9hnVXTWR+wAw9gG6w",
      nonce: params.nonce,
      paths: params.paths,
      exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
    };

    log("[didMethodsWithLit] payload:", payload);

    const response = await signWithLit(
      payload,
      contextParam
    );

    log("[didMethodsWithLit] response:", response);

    const general = toGeneralJWS(response);

    log("[didMethodsWithLit] general:", general);

    return general;
  },
  did_createJWS: async (contextParam: ContextWithLit, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split("#")[0];
    if (requestDid !== contextParam.did) throw new RPCError(4100, `Unknown DID: ${contextParam.did}`);
    const jws = await signWithLit(params.payload, contextParam, params.protected);

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

  constructor(contextParam: ContextWithLit) {
    const handler = createHandler<ContextWithLit, DIDProviderMethodsWithLit>(
      didMethodsWithLit
    );
    this._handle = async (msg) => {
      log("[Secp256k1ProviderWithLit] this._handle(msg):", msg);
      const _handler = await handler(contextParam, msg);
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
