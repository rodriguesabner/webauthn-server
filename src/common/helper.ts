import base64url from "base64url";

function decodeRegisterCredentials(opts: any){
    const {credentialPublicKey, credentialID} = opts;
    const base64PublicKey = base64url.encode(credentialPublicKey);
    const base64CredentialID = base64url.encode(credentialID);

    return {
        base64CredentialID,
        base64PublicKey,
    }
}
function decodeAuthCredentials(opts: any){
    const {credentialPublicKey, credentialID} = opts;
    const base64PublicKey = base64url.toBuffer(credentialPublicKey);
    const base64CredentialID = base64url.toBuffer(credentialID);

    return {
        base64CredentialID,
        base64PublicKey,
    }
}

function clientDataToJson(credential: any){
    const clientDataBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');
    const clientData = JSON.parse(clientDataBuffer.toString());
    return clientData;
}

function extractDomain(url: string){
    const urlParts = url.split('.');
    if(urlParts.length < 3){
        throw new Error('Invalid URL');
    }

    const domain = urlParts[1] + '.' + urlParts[2];
    return domain;
}

export {
    decodeRegisterCredentials,
    decodeAuthCredentials,
    clientDataToJson,
    extractDomain
}
