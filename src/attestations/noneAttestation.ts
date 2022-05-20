import base64url from "base64url";
import elliptic from "elliptic";
import nodeRSA from "node-rsa";
import cbor from "cbor";
import {COSEECDHAtoPKCS, hash, parseAuthData} from "../common/common";
import {COSE_KEYS, COSE_KTY, COSE_RSA_SCHEME} from "../common/cose";

function noneAttestation(webAuthnResponse: any) {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.attestationObject);
    let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    const authDataStruct = parseAuthData(attestationStruct.authData);

    const publicKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
    if (publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.EC2) {
        const ansiKey = COSEECDHAtoPKCS(publicKeyCose);

        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: ansiKey,
                counter: authDataStruct.counter,
                credID: base64url(authDataStruct.credID)
            }
        };
    } else if (publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.RSA) {
        // @ts-ignore
        const signingScheme = COSE_RSA_SCHEME[publicKeyCose.get(COSE_KEYS.alg)];
        // @ts-ignore
        const key = new nodeRSA(undefined, {signingScheme});
        key.importKey({
            n: publicKeyCose.get(COSE_KEYS.n),
            e: publicKeyCose.get(COSE_KEYS.e)
        }, 'components-public');
        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: key.exportKey('pkcs1-public-pem'),
                counter: authDataStruct.counter,
                credID: base64url(authDataStruct.credID)
            }
        };
    } else if (publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.OKP) {
        const x = publicKeyCose.get(COSE_KEYS.x);
        const key = new elliptic.eddsa('ed25519');
        key.keyFromPublic(x);

        return {
            verified: true,
            authrInfo: {
                fmt: 'none',
                publicKey: key,
                counter: authDataStruct.counter,
                credID: base64url(authDataStruct.credID)
            }
        };
    }
}

export default noneAttestation;


