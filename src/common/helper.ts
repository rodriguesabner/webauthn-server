import crypto from "crypto";
import base64url from "base64url";

async function verifySignature(signature: any, data: any, publicKey: any) {
    return crypto
        .createVerify("SHA256")
        .update(data)
        .verify(publicKey, signature);
}

const randomBase64URLBuffer = (len: number) => {
    len = len || 32;
    let buff = crypto.randomBytes(len);
    return base64url(buff);
}

const randomHex32String = () => {
    return crypto.randomBytes(32).toString("hex");
}

function serverGetAssertion(authenticators: any) {
    const rpId = process.env.RP_ID || "webauthn-beta.vercel.app";
    const allowCreds = authenticators.map((authr: any) => {
        return {
            type: "public-key",
            id: authr.credID,
        };
    });
    return {
        challenge: base64url.encode("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII="),
        allowCredentials: allowCreds,
        timeout: 60000,
    };
}

export {
    verifySignature,
    randomBase64URLBuffer,
    randomHex32String,
    serverGetAssertion
}
