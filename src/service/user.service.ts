import base64url from "base64url";
import { createHash } from "crypto";
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server";
import UserRepository from "../repository/user.repository";
import { UserModel } from "../model/user.model";
import { extractDomain, clientDataToJson, decodeAuthCredentials, decodeRegisterCredentials } from "../common/helper";

class UserService {
    private userRepository: UserRepository;
    private WEBAUTHN_TIMEOUT: { FIVE_MINUTES: number };
    private rpId: string;
    private rpInfo: string;

    constructor() {
        this.userRepository = new UserRepository();

        this.rpId = "webauthn-beta.vercel.app"
        this.rpInfo = "Abner ROdrigues"
        this.WEBAUTHN_TIMEOUT = {
            FIVE_MINUTES: 1000 * 60 * 5,
        };
    }

    async getCredentials(email: string) {
        const existentUser = await this.userRepository.findUserByUnique({ query: email });
        if (!existentUser) {
            throw new Error("User not found");
        }

        return existentUser.credentials;
    }

    async authenticate(opts: any) {
        const allowCredentials = [];

        const existentUser = await this.userRepository.findUserByUnique({ query: opts.name });
        if (!existentUser) throw new Error("User not found");

        const userVerification = opts.userVerification || 'preferred';
        const timeout = this.WEBAUTHN_TIMEOUT.FIVE_MINUTES;

        for (let cred of existentUser.credentials) {
            if (cred) {
                allowCredentials.push({
                    id: base64url.toBuffer(cred.credentialID),
                    transports: [],
                    type: 'public-key',
                });
            }
        }

        const options = generateAuthenticationOptions({
            timeout,
            // @ts-ignore
            allowCredentials,
            challenge: base64url.toBuffer(existentUser.challenge),
            userVerification,
        });

        return options;
    }

    async authenticateResponse(credential: any, origin: string) {
        const domain = extractDomain(origin);
        if (domain !== "vercel.app") {
            throw new Error("Domain not supported");
        }

        const clientData = clientDataToJson(credential);

        const existentUser = await UserModel.findOne({ challenge: clientData.challenge });
        if (existentUser == null) throw new Error('User not found');

        const userInfoCredentials = existentUser.credentials.find(
            (user: any) => user.credentialID === credential.id
        );

        if (!userInfoCredentials) {
            throw new Error('Authenticating credential not found.');
        }

        const decodedUserInfo = decodeAuthCredentials(userInfoCredentials);

        const authenticator = {
            credentialPublicKey: decodedUserInfo.base64PublicKey,
            credentialID: decodedUserInfo.base64CredentialID,
            counter: userInfoCredentials.counter,
            transports: userInfoCredentials.transports
        }

        const originToRpID = existentUser.origin.replace(/^https?:\/\//, '');

        const verification = verifyAuthenticationResponse({
            credential,
            expectedChallenge: existentUser.challenge,
            expectedOrigin: existentUser.origin,
            expectedRPID: originToRpID,
            authenticator,
        });

        const { verified, authenticationInfo } = verification;

        if (!verified) throw 'User verification failed.';

        await existentUser.updateOne({
            $set: {
                counter: authenticationInfo.newCounter,
                last_used: new Date(),
            }
        });

        return existentUser;
    }

    async register(opts: any) {
        const existentUser = await this.userRepository.findUserByUnique({ query: opts.name });

        const newUserData = {
            name: opts.name,
            displayName: opts.displayName
        };

        let generatedCred = this.generateCredentials({
            ...newUserData,
            origin: opts.origin,
            userAgent: opts.userAgent
        });

        if (existentUser) {
            return generatedCred;
        }

        const newUser = new UserModel({
            user_id: generatedCred.user.id,
            name: generatedCred.user.name,
            displayName: generatedCred.user.displayName,
            challenge: generatedCred.challenge,
            origin: opts.origin,
            credentials: []
        });

        newUser.save();

        return generatedCred;
    }

    generateCredentials(opts: any): any {
        const encoder = new TextEncoder();

        const {name, displayName, origin} = opts;
        const data = encoder.encode(`${name}${displayName}`)
        const userId = createHash('sha256').update(data).digest();

        const domain = extractDomain(origin);
        if (domain !== "vercel.app") {
            throw new Error("Domain not supported");
        }

        const user = {
            id: base64url.encode(Buffer.from(userId)),
            name,
            displayName
        };

        let options: any = {};

        if (!opts.userAgent.platform.includes("Linux")) {
            Object.assign(options, {
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                },
            })
        }

        const originToRpID = origin.replace(/^https?:\/\//, '');

        options = generateRegistrationOptions({
            rpName: this.rpInfo,
            rpID: originToRpID,
            userID: user.id,
            userName: user.name,
            userDisplayName: user.displayName,
            timeout: this.WEBAUTHN_TIMEOUT.FIVE_MINUTES,
            attestationType: 'indirect',
            // attestationType:  'direct',
            // obs: direct nao funciona no browser: brave.
        });

        return options;
    };

    async registerResponse(credential: any, browserInfo: any, origin?: string) {
        const { transports, clientExtensionResults } = credential;

        const clientData = clientDataToJson(credential);

        const existentUser = await this.userRepository.findUserByChallenge(clientData.challenge);
        if (existentUser == null) throw new Error('User not found');

        const expectedChallenge = existentUser.challenge;
        const expectedOrigin = existentUser.origin;

        const domain = extractDomain(expectedOrigin);
        if (domain !== "vercel.app") {
            throw new Error("Domain not supported");
        }

        const originToRpID = expectedOrigin.replace(/^https?:\/\//, '');

        const verification = await verifyRegistrationResponse({
            credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID: originToRpID,
        });

        const { verified, registrationInfo } = verification;
        if (!verified || !registrationInfo) throw 'User verification failed.';

        const decodedRegistrationInfo = decodeRegisterCredentials(registrationInfo);

        const newCredentials = {
            credentialID: decodedRegistrationInfo.base64CredentialID,
            credentialPublicKey: decodedRegistrationInfo.base64PublicKey,
            counter: registrationInfo.counter,
            registered: new Date().getTime(),
            user_verifying: registrationInfo.userVerified,
            authenticatorAttachment: "platform",
            browser: browserInfo?.browser,
            os: browserInfo?.os,
            platform: browserInfo?.platform,
            transports: transports != null ? transports : [],
            clientExtensionResults,
        };

        await this.userRepository.setCredentialsUserByChallenge({
            challenge: existentUser.challenge,
            credentials: newCredentials
        });

        return newCredentials;
    }

}

export default UserService;
