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
        const existentUser = await UserModel.findOne({email: email});
        if (!existentUser) {
            return res.status(404).json({message: 'User not found'});
        }

        const credentials = existentUser.credentials;
        return res.status(200).json(credentials);
    }

    async login(req: Request, res: Response) {
        const requestOptions = req.body;
        const {name} = req.body;

        const WEBAUTHN_TIMEOUT = 1000 * 60 * 5; // 5 minutes

        if (!name)
            return res.status(400).send('Missing name field');

        const existentUser: any = await UserModel.findOne({name: name});

        if (!existentUser)
            return res.status(404).send('User does not exist');

        const userVerification = requestOptions.userVerification || 'preferred';
        const timeout = WEBAUTHN_TIMEOUT;
        const rpID = 'webauthn-beta.vercel.app';

        // if (requestOptions.allowCredentials) {
        //     for (let cred of existentUser.credentials) {
        //         // Find the credential in the list of allowed credentials.
        //         const _cred: any = requestOptions.allowCredentials.find((_cred: any) => {
        //             return _cred.credentialID == cred.credentialID;
        //         });
        //         // If the credential is found, add it to the list of allowed credentials.
        //         if (_cred) {
        //             allowCredentials.push({
        //                 id: base64url.toBuffer(_cred.id),
        //                 type: 'public-key',
        //                 transports: existentUser.transports,
        //             });
        //         }
        //     }
        // }

        const options = generateAuthenticationOptions({
            timeout,
            // @ts-ignore
            // allowCredentials,
            userVerification,
            rpID
        });

        return res.status(200).json(options);
    }

    async register(req: Request, res: Response) {
        const body = req.body;

        let generateCredentials = this.userService.generateCredentials(body);

        const user = await UserModel.findOne({name: body.name});
        if (user) {
            return res.status(200).json(generateCredentials);
        }

        const newUser = new UserModel({
            user_id: generateCredentials.user.id,
            name: generateCredentials.user.name,
            challenge: generateCredentials.challenge,
        });

        newUser.save();

        return res.status(200).json(generateCredentials);
    }

    async response(req: Request, res: Response) {
        const credential = req.body;

        const clientDataBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');
        const clientData = JSON.parse(clientDataBuffer.toString());

        const existentUser = await UserModel.findOne({challenge: clientData.challenge});

        // @ts-ignore
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

        const credentials = {
            credentialID: base64CredentialID,
            credentialPublicKey: base64PublicKey,
            counter,
            registered: new Date().getTime(),
            user_verifying: registrationInfo.userVerified,
            authenticatorAttachment: "platform",
            browser: req.useragent?.browser,
            os: req.useragent?.os,
            platform: req.useragent?.platform,
            transports,
            clientExtensionResults,
        };

        await UserModel.updateOne(
            {challenge: existentUser.challenge},
            {$push: {credentials: credentials}}
        );

        return res.status(200).json(credentials);
    }

    async authResponse(req: Request, res: Response) {
        // @ts-ignore
        const session = Object.values(req.sessionStore.sessions)[0];
        // @ts-ignore
        const sessionToJson = JSON.parse(session);

        const expectedChallenge = sessionToJson.challenge;
        const expectedRPID = "webauthn-beta.vercel.app";
        let expectedOrigin = "https://webauthn-beta.vercel.app";

        try {
            const claimedCred = req.body;

            const storagedUser = await UserModel.findOne({email: 'abner@gmail.com'});
            let storedCred = storagedUser.credentials.find((cred: any) => cred.credentialID === claimedCred.id);

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
            res.status(400).json({status: false, error});
        }
    }
}

export default UserController;
