import base64url from "base64url";
import elliptic from "elliptic";
import nodeRSA from "node-rsa";
import cbor from "cbor";
import {COSEECDHAtoPKCS, hash, parseAuthData} from "../common/common";
import {COSE_ALG_HASH, COSE_CRV, COSE_KEYS, COSE_KTY, COSE_RSA_SCHEME} from "../common/cose";

async function noneAttestation(ctapCredentialResponse: any){
    const authenticatorDataStruct = parseAuthData(ctapCredentialResponse.authData);


    const publicKeyCose = cbor.decodeAllSync(authenticatorDataStruct.COSEPublicKey)[0];
    if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.EC2){
        const ansiKey = COSEECDHAtoPKCS(publicKeyCose);

        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: ansiKey,
                counter: authenticatorDataStruct.counter,
                credID: base64url(authenticatorDataStruct.credID)
            }
        };
    }
    else if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.RSA){
        // @ts-ignore
        const signingScheme = COSE_RSA_SCHEME[publicKeyCose.get(COSE_KEYS.alg)];
        // @ts-ignore
        const key = new nodeRSA(undefined, { signingScheme });
        key.importKey({
            n: publicKeyCose.get(COSE_KEYS.n),
            e: publicKeyCose.get(COSE_KEYS.e)
        }, 'components-public');
        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: key.exportKey('pkcs1-public-pem'),
                counter: authenticatorDataStruct.counter,
                credID: base64url(authenticatorDataStruct.credID)
            }
        };
    }
    else if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.OKP){
        const x = publicKeyCose.get(COSE_KEYS.x);
        const key = new elliptic.eddsa('ed25519');
        key.keyFromPublic(x);

        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: key,
                counter: authenticatorDataStruct.counter,
                credID: base64url(authenticatorDataStruct.credID)
            }
        };
    }
}

export default noneAttestation;


