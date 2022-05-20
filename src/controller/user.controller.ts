import {Request, Response} from "express";
import UserService from "../service/user.service";
import {serverGetAssertion} from "../common/helper";
import base64url from "base64url";
import {
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

class UserController {
    private userService: UserService;
    private stored: any = [];

    constructor() {
        this.userService = new UserService();
    }

    async login(req: Request, res: Response) {
        const WEBAUTHN_TIMEOUT = 1000 * 60 * 5; // 5 minutes

        const {email} = req.body;
        if (!email)
            return res.status(400).send('Missing email field');

        const user = this.stored.find((user: any) => user.email === email);
        if (!user)
            return res.status(404).send('User does not exist');

        const requestOptions = req.body;

        const userVerification = requestOptions.userVerification || 'preferred';
        const timeout = WEBAUTHN_TIMEOUT;
        const rpID = 'webauthn-beta.vercel.app';

        const options = generateAuthenticationOptions({
            timeout,
            // allowCredentials,
            userVerification,
            rpID
        });

        // @ts-ignore
        req.session.challenge = options.challenge;
        // @ts-ignore
        req.session.timeout = getNow() + WEBAUTHN_TIMEOUT;

        return res.status(200).json(options);
    }

    async register(req: Request, res: Response) {
        const {name, displayName} = req.body;

        let credentials = this.userService.generateCredentials({name, displayName});

        let userExists = this.stored.find((user: any) => user.name === name);
        if (userExists) {
            userExists.challenge = credentials.challenge;
            userExists.email = credentials.user.displayName;
        } else {
            this.stored.push({
                challenge: credentials.challenge,
                name,
            });
        }

        // @ts-ignore
        req.session.challenge = credentials.challenge;
        // @ts-ignore
        req.session.timeout = new Date().getTime() + credentials.timeout;
        req.session.save();

        return res.status(200).json(credentials);
    }

    async response(req: Request, res: Response) {
        const credential = req.body;

        const currentSession = req.session.id;
        // @ts-ignore
        const session = Object.values(req.sessionStore.sessions)[0];
        // @ts-ignore
        const sessionToJson = JSON.parse(session);
        console.log(session);

        // @ts-ignore
        const expectedChallenge = sessionToJson.challenge;
        const expectedRPID = "webauthn-beta.vercel.app";

        let expectedOrigin = "https://webauthn-beta.vercel.app";

        const verification = await verifyRegistrationResponse({
            credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
        });

        const { verified, registrationInfo } = verification;

        if (!verified || !registrationInfo) {
            throw 'User verification failed.';
        }

        const { credentialPublicKey, credentialID, counter }: any = registrationInfo;
        const base64PublicKey = base64url.encode(credentialPublicKey);
        const base64CredentialID = base64url.encode(credentialID);
        const { transports, clientExtensionResults } = credential;

        let user = this.stored.find((user: any) => user.name === 'abner@gmail.com');
        const newData = {
            user_id: user.user_id,
            credentialID: base64CredentialID,
            credentialPublicKey: base64PublicKey,
            counter,
            registered: new Date().getTime(),
            user_verifying: registrationInfo.userVerified,
            authenticatorAttachment: "undefined",
            transports,
            clientExtensionResults,
        }

        user = newData;

        return res.status(200).json(credential);
    }

    async authResponse(req: Request, res: Response) {
        // @ts-ignore
        const session = Object.values(req.sessionStore.sessions)[0];
        // @ts-ignore
        const sessionToJson = JSON.parse(session);
        console.log(session);

        const expectedChallenge = sessionToJson.challenge;
        const expectedRPID = "webauthn-beta.vercel.app";
        let expectedOrigin = "https://webauthn-beta.vercel.app";

        try {
            const claimedCred = req.body;

            let credentials = this.stored.find((user: any) => user.name === 'abner@gmail.com');
            let storedCred = credentials.find((cred: any) => cred.credentialID === claimedCred.id);

            if (!storedCred) {
                throw 'Authenticating credential not found.';
            }

            const base64PublicKey = base64url.toBuffer(storedCred.credentialPublicKey);
            const base64CredentialID = base64url.toBuffer(storedCred.credentialID);
            const { counter, transports } = storedCred;

            const authenticator = {
                credentialPublicKey: base64PublicKey,
                credentialID: base64CredentialID,
                counter,
                transports
            }

            const verification = verifyAuthenticationResponse({
                credential: claimedCred,
                expectedChallenge,
                expectedOrigin,
                expectedRPID,
                authenticator,
            });

            const { verified, authenticationInfo } = verification;

            if (!verified) {
                throw 'User verification failed.';
            }

            storedCred.counter = authenticationInfo.newCounter;
            storedCred.last_used = new Date().getTime();

            // @ts-ignore
            delete req.session.challenge;
            // @ts-ignore
            delete req.session.timeout;
            res.json(storedCred);
        } catch (error) {
            console.error(error);

            // @ts-ignore
            delete req.session.challenge;
            // @ts-ignore
            delete req.session.timeout;
            res.status(400).json({ status: false, error });
        }
    }
}

export default UserController;
