import base64url from "base64url";
import {createHash} from "crypto";
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server";
import UserRepository from "../repository/user.repository";
import {UserModel} from "../model/user.model";
import {clientDataToJson, decodeAuthCredentials, decodeRegisterCredentials} from "../common/helper";

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
        const existentUser = await this.userRepository.findUserByUnique({query: email});
        if (!existentUser) {
            throw new Error("User not found");
        }

        return existentUser.credentials;
    }

    async authenticate(opts: any) {
        const allowCredentials = [];

        const existentUser = await this.userRepository.findUserByUnique({query: opts.name});
        if (!existentUser) throw new Error("User not found");

        const userVerification = opts.userVerification || 'preferred';
        const timeout = this.WEBAUTHN_TIMEOUT.FIVE_MINUTES;
        const rpID = this.rpId;

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
            rpID
        });

        return options;
    }

    async authenticateResponse(credential: any) {
        const clientData = clientDataToJson(credential);

        const existentUser = await UserModel.findOne({challenge: clientData.challenge});
        if (existentUser == null) throw new Error('User not found');

        let expectedOrigin = ["https://webauthn-beta.vercel.app"];

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

        const verification = verifyAuthenticationResponse({
            credential,
            expectedChallenge: existentUser.challenge,
            expectedOrigin,
            expectedRPID: this.rpId,
            authenticator,
        });

        const {verified, authenticationInfo} = verification;

        if (!verified) throw 'User verification failed.';

        userInfoCredentials.counter = authenticationInfo.newCounter;
        userInfoCredentials.last_used = new Date().getTime();

        return existentUser;
    }

    async register(opts: any) {
        let credentials;

        const existentUser = await this.userRepository.findUserByUnique({query: opts.name});
        if (existentUser != null) {
            credentials = existentUser.credentials;
        }

        const newUserData = {
            name: opts.name,
            displayName: opts.displayName
        };

        let generatedCred = this.generateCredentials(credentials, {
            ...newUserData,
            ...opts.authenticatorSelection,
        });

        if (existentUser) {
            return generatedCred;
        }

        const newUser = new UserModel({
            user_id: generatedCred.user.id,
            name: generatedCred.user.name,
            displayName: generatedCred.user.displayName,
            challenge: generatedCred.challenge,
            credentials: []
        });

        newUser.save();

        return generatedCred;
    }

    generateCredentials(userAuthenticators: any, opts: any): any {
        const encoder = new TextEncoder();

        const name = opts.name;
        const displayName = opts.displayName;
        const data = encoder.encode(`${name}${displayName}`)
        const userId = createHash('sha256').update(data).digest();

        const user = {
            id: base64url.encode(Buffer.from(userId)),
            name,
            displayName
        };

        let excludeCredentials;
        if (userAuthenticators != null) {
            excludeCredentials = userAuthenticators.map((authenticator: any) => ({
                id: authenticator.credentialID,
                type: 'public-key',
            }));
        }

        const options = generateRegistrationOptions({
            rpName: this.rpInfo,
            rpID: this.rpId,
            userID: user.id,
            userName: user.name,
            userDisplayName: user.displayName,
            timeout: this.WEBAUTHN_TIMEOUT.FIVE_MINUTES,
            attestationType: 'indirect',
            excludeCredentials
        });

        return options;
    };

    async registerResponse(credential: any, browserInfo: any) {
        const {transports, clientExtensionResults} = credential;

        const clientData = clientDataToJson(credential);

        const existentUser = await this.userRepository.findUserByChallenge(clientData.challenge);
        if (existentUser == null) throw new Error('User not found');

        const expectedChallenge = existentUser.challenge;

        const expectedOrigin = "https://webauthn-beta.vercel.app";

        const verification = await verifyRegistrationResponse({
            credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID: this.rpId,
        });

        const {verified, registrationInfo} = verification;
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
