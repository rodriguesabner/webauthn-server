import base64url from "base64url";

const token = 'TUlJQmt6Q0NBVGlnQXdJQkFqQ0NBWk13Z2dFNG9BTUNBUUl3Z2dHVE1JST0';
const newChallenge = "AE1JSUJrekNDQVRpZ0F3SUJBakNDQVpNd2dnRTRvQU1DQVFJd2dnR1RNSUk";

// newChallenge
// MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII

// token
// MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII=

const tok = base64url.decode(token, "utf8");
const newC = base64url.encode('mGutgJZXFrUCEuexqd1VQ6JectjTml0W2hrTsbDixfQ');
// console.log('token -> ', tok);
console.log('newchallenge ->', newC);

// {
//     "type": "webauthn.create",
//     "challenge": "AE1JSUJrekNDQVRpZ0F3SUJBakNDQVpNd2dnRTRvQU1DQVFJd2dnR1RNSUk",
//     "origin": "https://webauthn-beta.vercel.app"
// }
