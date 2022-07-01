import { ES256KSigner, Signer, createJWS } from "did-jwt";

import type {
  AuthParams,
  CreateJWSParams,
  DIDMethodName,
  DIDProviderMethods,
  DIDProvider,
  GeneralJWS,
  DecryptJWEParams,
} from "dids";

import { toGeneralJWS, toJose, toStableObject, sha256, log } from "./util.js";

import type {
  HandlerMethods,
  RPCRequest,
  RPCResponse,
  SendRequestFunc,
  RPCConnection,
} from "rpc-utils";

import { RPCError, createHandler } from "rpc-utils";

import * as u8a from "uint8arrays";
import elliptic from "elliptic";

import LitJsSdk from "lit-js-sdk";
log("LitJsSdk:", LitJsSdk, true);

const EC = elliptic.ec;
const ec = new EC("secp256k1");

interface Context {
  did: string;
  secretKey: Uint8Array;
}

export function encodeDID(publicKey: Uint8Array): string {
  const bytes = new Uint8Array(publicKey.length + 2);
  bytes[0] = 0xe7; // secp256k1 multicodec
  // The multicodec is encoded as a varint so we need to add this.
  // See js-multicodec for a general implementation
  bytes[1] = 0x01;
  bytes.set(publicKey, 2);
  return `did:key:z${u8a.toString(bytes, "base58btc")}`;
}

const sign = async (
  payload: Record<string, any> | string,
  did: string,
  secretKey: Uint8Array,
  protectedHeader: Record<string, any> = {}
) => {
  const kid = `${did}#${did.split(":")[2]}`;
  const signer = ES256KSigner(secretKey);

  log("signer:", signer);

  const header = toStableObject(
    Object.assign(protectedHeader, { kid, alg: "ES256K" })
  );

  return createJWS(
    typeof payload === "string" ? payload : toStableObject(payload),
    signer,
    header
  );
};

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
    );
    return toGeneralJWS(response);
  },
  did_createJWS: async (
    { did, secretKey },
    params: CreateJWSParams & { did: string }
  ) => {
    const requestDid = params.did.split("#")[0];
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`);
    const jws = await sign(params.payload, did, secretKey, params.protected);
    return { jws: toGeneralJWS(jws) };
  },
  did_decryptJWE: async () => {
    // Not implemented
    return { cleartext: "" };
  },
};

export class Secp256k1Provider implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>;

  constructor(seed: Uint8Array) {
    const publicKey = ec.keyFromPrivate(seed).getPublic(true, "array");
    const did = encodeDID(Uint8Array.from(publicKey));

    const handler = createHandler<Context, DIDProviderMethods>(didMethods);
    this._handle = async (msg) => {
      const _handler = await handler({ did, secretKey: seed }, msg);
      return _handler;
    };
  }

  get isDidProvider(): boolean {
    return true;
  }

  async send<Name extends DIDMethodName>(
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return await this._handle(msg);
  }
}

// --------------------------------------------------
// -                    WITH LIT                    -
// --------------------------------------------------

interface ContextWithLit {
  did: string;
}

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

const litActionSignAndGetSignature = async (dataToSign: Uint8Array) => {
  log("litActionSignAndGetSignature:", dataToSign);

  //  -- validate
  if (dataToSign == undefined) throw Error("dataToSign cannot be empty");

  // -- prepare
  const DATA_TO_SIGN_IN_STRING = Array.from(dataToSign).toString();

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
};

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

export function ES256KSignerWithLit(): Signer {
  const recoverable = false;

  return async (data: string | Uint8Array): Promise<string> => {
    log("ES256KSignerWithLit:", sha256(data));

    const signature = (await litActionSignAndGetSignature(sha256(data))).sig1;
    // log("ES256KSignerWithLit signature:", signature);

    // const { r, s, recoveryParam }: elliptic.ec.Signature = keyPair.sign(sha256(data))
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

const didMethodsWithLit: HandlerMethods<
  ContextWithLit,
  DIDProviderMethodsWithLit
> = {
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

export declare type DIDMethodNameWithLit = keyof DIDProviderMethodsWithLit;

export declare type DIDProviderWithLit =
  RPCConnection<DIDProviderMethodsWithLit>;

//
// Lit version of Secp256k1Provider without private key
//
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
