import crypto from "crypto";
import base64url from "base64url";

function verifySignature(signature: any, data: any, publicKey: any) {
    try {
        const verifier = crypto.createVerify("RSA-SHA256");
        verifier.update(data);
        return verifier.verify(publicKey, signature);
    } catch (e: any) {
        console.log(e);
        throw new Error(e);
    }
}

const randomBase64URLBuffer = (len: number) => {
    len = len || 32;
    let buff = crypto.randomBytes(len);
    return base64url(buff);
}

const randomHex32String = () => {
    return crypto.randomBytes(32).toString("hex");
}

function serverGetAssertion(user: any) {
    const allowCreds = user.authenticators.map((authr: any) => {
        return {
            type: "public-key",
            id: authr.id,
        };
    });

    return {
        challenge: user.challenge,
        allowCredentials: allowCreds,
        requireResidentKey: false,
        timeout: 5000,
    };
}

export {
    verifySignature,
    randomBase64URLBuffer,
    randomHex32String,
    serverGetAssertion
}
