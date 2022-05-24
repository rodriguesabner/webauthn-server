import {Request, Response} from "express";
import UserService from "../service/user.service";
import base64url from "base64url";
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from '@simplewebauthn/server';
import {UserModel} from "../model/user.model";

class UserController {
    private userService: UserService;

    constructor() {
        this.userService = new UserService();
    }

    async getCredentials(req: Request, res: Response) {
        const {email} = req.query;
        const existentUser = await UserModel.findOne({name: email});
        if (!existentUser) {
            return res.status(404).json({message: 'User not found'});
        }

        const credentials = existentUser.credentials;
        return res.status(200).json(credentials);
    }

    async login(req: Request, res: Response) {
        const requestOptions = req.body;
        const {name} = req.body;

        const allowCredentials = [];

        const WEBAUTHN_TIMEOUT = 1000 * 60 * 5; // 5 minutes

        if (!name)
            return res.status(400).send('Missing name field');

        const existentUser = await UserModel.findOne({name: name});
        if (!existentUser)
            return res.status(404).send('User does not exist');

        const userVerification = requestOptions.userVerification || 'preferred';
        const timeout = WEBAUTHN_TIMEOUT;
        const rpID = 'webauthn-beta.vercel.app';

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

        return res.status(200).json(options);
    }

    async register(req: Request, res: Response) {
        const {name, displayName} = req.body;
        let credentials;

        if(!name || !displayName)
            return res.status(400).send('Missing name field');

        const existentUser = await UserModel.findOne({name: name});
        if (existentUser != null) {
            credentials = existentUser.credentials;
        }

        const userReq = {name, displayName};
        let generateCredentials = this.userService.generateCredentials(credentials, userReq);

        if (existentUser) {
            return res.status(200).json(generateCredentials);
        }

        try {
            const newUser = new UserModel({
                user_id: generateCredentials.user.id,
                name: generateCredentials.user.name,
                displayName: generateCredentials.user.displayName,
                challenge: generateCredentials.challenge,
                credentials: []
            });

            newUser.save();
        } catch (e: any) {
            throw new Error(e);
        }

        return res.status(200).json(generateCredentials);
    }

    async response(req: Request, res: Response) {
        const credential = req.body;

        const clientDataBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');
        const clientData = JSON.parse(clientDataBuffer.toString());

        const existentUser = await UserModel.findOne({challenge: clientData.challenge});

        const expectedChallenge = existentUser.challenge;
        const expectedRPID = "webauthn-beta.vercel.app";

        let expectedOrigin = "https://webauthn-beta.vercel.app";

        const verification = await verifyRegistrationResponse({
            credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
        });

        const {verified, registrationInfo} = verification;

        if (!verified || !registrationInfo) {
            throw 'User verification failed.';
        }

        const {credentialPublicKey, credentialID, counter}: any = registrationInfo;
        const base64PublicKey = base64url.encode(credentialPublicKey);
        const base64CredentialID = base64url.encode(credentialID);
        const {transports, clientExtensionResults} = credential;

        const newCredentials = {
            credentialID: base64CredentialID,
            credentialPublicKey: base64PublicKey,
            counter,
            registered: new Date().getTime(),
            user_verifying: registrationInfo.userVerified,
            authenticatorAttachment: "platform",
            browser: req.useragent?.browser,
            os: req.useragent?.os,
            platform: req.useragent?.platform,
            transports: transports != null ? transports : [],
            clientExtensionResults,
        };


        await UserModel.updateOne(
            {challenge: existentUser.challenge},
            {$set: {credentials: newCredentials}}
        );

        return res.status(200).json(newCredentials);
    }

    async authResponse(req: Request, res: Response) {
        const credential = req.body;
        if (credential.response) {
            const clientDataBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');
            const clientData = JSON.parse(clientDataBuffer.toString());

            const existentUser = await UserModel.findOne({challenge: clientData.challenge});

            // @ts-ignore
            const expectedChallenge = existentUser.challenge;
            const expectedRPID = ["localhost:8080", "webauthn-beta.vercel.app"];
            let expectedOrigin = ["https://vercel.app", "https://webauthn-beta.vercel.app"];

            try {
                const claimedCred = req.body;
                let storedCred = existentUser.credentials.find((cred: any) => cred.credentialID === claimedCred.id);

                if (!storedCred) {
                    throw 'Authenticating credential not found.';
                }

                const base64PublicKey = base64url.toBuffer(storedCred.credentialPublicKey);
                const base64CredentialID = base64url.toBuffer(storedCred.credentialID);
                const {counter, transports} = storedCred;

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

                const {verified, authenticationInfo} = verification;

                if (!verified) {
                    throw 'User verification failed.';
                }

                storedCred.counter = authenticationInfo.newCounter;
                storedCred.last_used = new Date().getTime();

                res.status(200).json(existentUser);
            } catch (error) {
                console.error(error);
                res.status(400).json({status: false, error});
            }
        } else {
            return res.status(400).json({error: 'response field is required'});
        }
    }
}

export default UserController;
