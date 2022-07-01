# secp256k1 key did provider with Lit Actions x PKP powered by Lit Protocol

This a a DID provider which integrated Lit Actions x PKP powered by Lit Protocol for `did:key` using secp256k1. It does not support encryption / JWE. It's a fork from [symfoni/key-did-provider-secp256k1](https://github.com/symfoni/key-did-provider-secp256k1) and was designed to be used with [Ceramic Network](https://ceramic.network/).

## Installation

```
yarn add key-did-provider-secp256k1-with-lit
```

## Usage

```js
import { 
    encodeDIDWithLit,  
    Secp256k1ProviderWithLit 
} from 'key-did-provider-secp256k1-with-lit';

import { CeramicClient } from '@ceramicnetwork/http-client'
import { TileDocument } from '@ceramicnetwork/stream-tile'
import { getResolver } from 'key-did-resolver'
import { DID } from 'dids'

const ceramic = new CeramicClient('https://ceramic-clay.3boxlabs.com')

const encodedDID = await encodeDIDWithLit();

const provider = new Secp256k1ProviderWithLit(encodedDID);

const did = new DID({ provider, resolver: getResolver() })

// -- authenticate
await did.authenticate();
ceramic.did = did;
console.log("DID:", did);

// -- write to ceramic stream
const doc = await TileDocument.create(ceramic, 'Hola hola ¿Cómo estás?');
console.log("Doc/StreamID:", doc.id.toString());

// -- read a ceramic stream
var loadDoc = await TileDocument.load(ceramic, doc.id.toString());
console.log("Specific doc:", loadDoc.content);
```

## License

Apache-2.0 OR MIT