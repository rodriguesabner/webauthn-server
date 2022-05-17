import base64url from "base64url";
import cbor from "cbor";
import {verifySignature} from "../common/helper";
import crypto from "crypto";
import verifyAndroidKeyAttestation from "../attestations/androidKeyStoreAttestation";
import verifyAndroidSafetyNetAttestation from "../attestations/androidSafetyNetAttestation";
import verifyAppleAnonymousAttestation from "../attestations/appleAnonymousAttestation";

class UserService {
    generateCredentials(): any {
        const email = 'abner@gmail.com'

        const user = {
            id: base64url.encode("b3ace817-8f11-4940-9322-6c151aabc49a"),
            name: email.split('@')[0],
            email: email,
        };


        const credentials = {
            challenge: base64url.encode("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII="),
            rp: {
                name: 'Zoox WebAuthN',
                id: 'webauthn-beta.vercel.app',
            },
            user: {
                id: user.id,
                name: user.name,
                displayName: user.email,
            },
            pubKeyCredParams: [
                {'type': 'public-key', 'alg': -7},
                {'type': 'public-key', 'alg': -257}
            ],
            authenticatorSelection: {
                userVerification: "required"
            },
            attestation: 'direct',
            timeout: 15000,
        };

        return credentials;
    };

    findAuthenticator(credID: any, authenticators: any) {
        for (const authr of authenticators) {
            if (authr.credID === credID) return authr;
        }
        throw new Error(`Unknown authenticator with credID ${credID}!`);
    }

    parseGetAssertAuthData(buffer: any) {
        const rpIdHash = buffer.slice(0, 32);
        buffer = buffer.slice(32);

        const flagsBuf = buffer.slice(0, 1);
        buffer = buffer.slice(1);

        const flagsInt = flagsBuf[0];
        const flags = {
            up: !!(flagsInt & 0x01),
            uv: !!(flagsInt & 0x04),
            at: !!(flagsInt & 0x40),
            ed: !!(flagsInt & 0x80),
            flagsInt,
        };

        const counterBuf = buffer.slice(0, 4);
        buffer = buffer.slice(4);

        const counter = counterBuf.readUInt32BE(0);

        return {rpIdHash, flagsBuf, flags, counter, counterBuf};
    }

    checkPEM(pubKey: any) {
        return pubKey.toString("base64").includes("BEGIN");
    }

    hash(data: any) {
        return crypto.createHash("SHA256").update(data).digest();
    }

    ASN1toPEM(pkBuffer: any) {
        if (!Buffer.isBuffer(pkBuffer))
            throw new Error("ASN1toPEM: input must be a Buffer");
        let type;
        if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
            pkBuffer = Buffer.concat([
                // @ts-ignore
                new Buffer.from(
                    "3059301306072a8648ce3d020106082a8648ce3d030107034200",
                    "hex"
                ),
                pkBuffer,
            ]);
            type = "PUBLIC KEY";
        } else type = "CERTIFICATE";
        const base64Certificate = pkBuffer.toString("base64");
        let PEMKey = "";

        for (let i = 0; i < Math.ceil(base64Certificate.length / 64); i++) {
            const start = 64 * i;
            PEMKey += base64Certificate.substr(start, 64) + "\n";
        }

        PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

        return PEMKey;
    }

    async verifyAuthenticatorAssertionResponse(
        webAuthnResponse: any,
        authenticators: any
    ) {
        const authr = this.findAuthenticator(webAuthnResponse.id, authenticators);
        const authenticatorData = base64url.toBuffer(
            webAuthnResponse.response.authenticatorData
        );

        let response = {verified: false};
        if (
            authr.fmt === "fido-u2f" ||
            authr.fmt === "packed" ||
            authr.fmt === "android-safetynet" ||
            authr.fmt === "android-key" ||
            authr.fmt === "apple" ||
            authr.fmt === "none"
        ) {
            let authrDataStruct = this.parseGetAssertAuthData(authenticatorData);

            if (!authrDataStruct.flags.up)
                throw new Error("User was NOT presented durring authentication!");

            const clientDataHash = this.hash(
                base64url.toBuffer(webAuthnResponse.response.clientDataJSON)
            );
            const signatureBase = Buffer.concat([
                authrDataStruct.rpIdHash,
                authrDataStruct.flagsBuf,
                authrDataStruct.counterBuf,
                clientDataHash,
            ]);
            const publicKey = this.checkPEM(authr.publicKey)
                ? authr.publicKey.toString("base64")
                : this.ASN1toPEM(base64url.toBuffer(authr.publicKey));
            const signature = base64url.toBuffer(webAuthnResponse.response.signature);
            response.verified = await verifySignature(
                signature,
                signatureBase,
                publicKey
            );

            if (response.verified) {
                // @ts-ignore
                if (response.counter <= authr.counter)
                    throw new Error("Authr counter did not increase!");

                authr.counter = authrDataStruct.counter;
            }
        }

        return response;
    }

    async verifyAuthenticatorAttestationResponse(credential: any) {
        const attestationBuffer = base64url.toBuffer(credential.attestationObject);
        const decodedAttestation = cbor.decodeAllSync(attestationBuffer)[0];

        let verification;

        if (decodedAttestation.fmt === "apple") {
            verification = verifyAppleAnonymousAttestation(credential);
        } else if (decodedAttestation.fmt === "android-key") {
            verification = verifyAndroidKeyAttestation(credential);
        } else if (decodedAttestation.fmt === "android-safetynet") {
            verification = verifyAndroidSafetyNetAttestation(credential);
        }

        const {verified, authrInfo}: any = verification;

        if (verified) {
            return {verified, authrInfo};
        } else {
            return {verified: false};
        }
    }
}

export default UserService;
