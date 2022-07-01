import { Signer, createJWS } from "did-jwt";
import type { AuthParams, CreateJWSParams } from "dids";
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc } from "rpc-utils";
import { RPCError, createHandler } from "rpc-utils";
import * as u8a from "uint8arrays";
import elliptic from "elliptic";
import LitJsSdk from "lit-js-sdk";
import { toGeneralJWS, toJose, toStableObject, sha256, log } from "./util.js";
import { ContextWithLit, DIDMethodNameWithLit, DIDProviderMethodsWithLit, DIDProviderWithLit, LitActionParams } from "./interfaces.js";

const ec = new elliptic.ec("secp256k1");

/**
 * 
 * Get the PKP public key
 * 
 * @returns { String } public key
 */
const getPKPPublicKey = async () => {
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
 * @param { jsParams } jsParams params that passed to the js code 
 * @returns { Object } signatures
 */
const litActionSignAndGetSignature = async (dataToSign: Uint8Array, jsParams :LitActionParams) => {
  log("litActionSignAndGetSignature:", dataToSign);

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
    jsParams
  });

  return signatures;
};

/**
 * Create a DID (decentralized identifier) by using the PKP public key
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
 *  @param { jsParams } jsParams params that passed to the js code 
 * 
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSignerWithLit(jsParams: LitActionParams): Signer {
  const recoverable = false;

  return async (data: string | Uint8Array): Promise<string> => {
    
    log("ES256KSignerWithLit:", sha256(data));

    const signature = (await litActionSignAndGetSignature(sha256(data), jsParams)).sig1;

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
  jsParams: LitActionParams
) => {
  log("[signWithLit] did:", did);

  const kid = `${did}#${did.split(":")[2]}`;

  log("[signWithLit] kid:", kid);

  const signer = ES256KSignerWithLit(jsParams);

  log("[signWithLit] signer:", signer);

  const header = toStableObject(
    Object.assign({}, { kid, alg: "ES256K" })
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
  did_authenticate: async ({ did, jsParams}, params: AuthParams) => {
    const response = await signWithLit(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did,
      jsParams
    );

    log("[didMethodsWithLit] response:", response);

    const general = toGeneralJWS(response);

    log("[didMethodsWithLit] general:", general);

    return general;
  },
  did_createJWS: async ({ did, jsParams }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split("#")[0];
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`);
    const jws = await signWithLit(params.payload, did, jsParams);

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

  constructor(did: string, jsParams: LitActionParams) {
    const handler = createHandler<ContextWithLit, DIDProviderMethodsWithLit>(
      didMethodsWithLit
    );
    this._handle = async (msg) => {
      log("[Secp256k1ProviderWithLit] this._handle(msg):", msg);
      const _handler = await handler({ did, jsParams}, msg);
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
