import { Signer, createJWS } from "did-jwt";
import type { AuthParams, CreateJWSParams } from "dids";
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc } from "rpc-utils";
import { RPCError, createHandler } from "rpc-utils";
import * as u8a from "uint8arrays";
import elliptic from "elliptic";
import LitJsSdk from "lit-js-sdk";
import { toGeneralJWS, toJose, toStableObject, sha256, log } from "./util.js";
import { ContextWithLit, DIDMethodNameWithLit, DIDProviderMethodsWithLit, DIDProviderWithLit, IPFSData, IPFSParam } from "./interfaces.js";
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
 * @param { IPFSParam } param
 * @returns 
 */
export async function uploadToIPFS(param: IPFSParam) : Promise<IPFSData> {

  log("[uploadToIPFS] param: ", param);

  const ipfs = await IPFS.create()

  const { path } = await ipfs.add(param.code)

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

  log("[getPKPPublicKey]");

  const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });

  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });

  await litNodeClient.connect();

  const signatures = await litNodeClient.executeJs({
    code: `
        const go = async () => {
          const toSign = [0];
          const sigShare = await LitActions.signEcdsa({ toSign, keyId: 1, sigName: "sig1" });
      };
      go();
    `,
    authSig,
  });

  return signatures.sig1.publicKey;
};

/**
 * 
 * Prompt user to sign an auth message from a web3 wallet (eg. Metamask), connect the Lit client to 
 * ask the nodes to execute some JS that signs our data in `Uint8array` format
 * 
 * @param dataToSign 
 * @returns { Object } signatures
 */
const litActionSignAndGetSignature = async (dataToSign: Uint8Array) => {

  log("[litActionSignAndGetSignature]:", dataToSign);

  //  -- validate
  if (dataToSign == undefined) throw Error("dataToSign cannot be empty");

  const code = `
    const go = async () => {

        // this is the string "${dataToSign}" for testing
        const toSign = [${Array.from(dataToSign).toString()}];
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
    code,
    authSig,
  });

  return signatures;
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
export function ES256KSignerWithLit(): Signer {

  log("[ES256KSignerWithLit]");

  const recoverable = false;

  return async (data: string | Uint8Array): Promise<string> => {
    
    log("ES256KSignerWithLit:", sha256(data));

    const signature = (await litActionSignAndGetSignature(sha256(data))).sig1;

    return toJose(
      {
        r: signature.r,
        s: signature.s,
        recoveryParam: signature.recid,
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
  did: string,
  protectedHeader: Record<string, any> = {}
) => {

  log("[signWithLit] did:", did);

  const kid = `${did}#${did.split(":")[2]}`;

  log("[signWithLit] kid:", kid);

  const signer = ES256KSignerWithLit();

  log("[signWithLit] signer:", signer);

  const header = toStableObject(
    Object.assign(protectedHeader, { kid, alg: "ES256K" })
  );

  log("[signWithLit] header:", header);

  log("[signWithLit] payload:", payload);

  return createJWS(
    typeof payload === "string" ? payload : toStableObject(payload),
    signer,
    header
  );
};


/**
 * Define DID methods that matches the "DIDProviderMethodsWithLit" type
 */
const didMethodsWithLit: HandlerMethods<ContextWithLit, DIDProviderMethodsWithLit> = {
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
    );

    log("[didMethodsWithLit] response:", response);

    const general = toGeneralJWS(response);

    log("[didMethodsWithLit] general:", general);

    return general;
  },
  did_createJWS: async ({ did }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split("#")[0];
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`);
    const jws = await signWithLit(params.payload, did, params.protected);

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
 * @example
 * ```typescript
 * const encodedDID = await encodeDIDWithLit();
 * 
 * const provider = new Secp256k1ProviderWithLit(encodedDID)
 * 
 * const did = new DID({ provider, resolver: getResolver() })
 * 
 * await did.authenticate();
 * 
 * ceramic.did = did
 * 
 * // -- Write stream (docId = streamId)
 * const doc = await TileDocument.create(ceramic, `${new Date().toLocaleTimeString()} Hola hola ¿Cómo estás?`);
 * 
 * console.log("doc:", doc);
 * ```
 */
export class Secp256k1ProviderWithLit implements DIDProviderWithLit {
  _handle: SendRequestFunc<DIDProviderMethodsWithLit>;

  constructor(did: string) {
    const handler = createHandler<ContextWithLit, DIDProviderMethodsWithLit>(
      didMethodsWithLit
    );
    this._handle = async (msg) => {
      log("[Secp256k1ProviderWithLit] this._handle(msg):", msg);
      const _handler = await handler({ did }, msg);
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
