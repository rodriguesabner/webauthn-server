import {Request, Response} from "express";
import UserService from "../service/user.service";
import {serverGetAssertion} from "../common/helper";
import base64url from "base64url";

class UserController {
    private userService: UserService;
    private stored: any = [];
    private email = "abner@gmail.com";

    constructor() {
        this.userService = new UserService();
    }

    async login(req: Request, res: Response) {
        const {email} = req.body;
        if (!email)
            return res.status(400).send('Missing email field');

        const user = this.stored.find((user: any) => user.email === this.email);
        if (!user)
            return res.status(400).send('User does not exist');

        const getAssertion: any = serverGetAssertion(user.authenticators);
        getAssertion.status = 'ok';

        return res.status(200).json(getAssertion);
    }

    async register(req: Request, res: Response) {
        const {email} = req.body;
        if (!email)
            return res.status(400).send('Missing email field');

        const user = {
            id: "b3ace817-8f11-4940-9322-6c151aabc49a",
            name: email.split('@')[0],
            email,
        };

        let makeCredChallenge: any = this.userService.serverMakeCred(user.id, user.email);
        makeCredChallenge.status = 'ok';

        // let userExists = this.stored.find((user: any) => user.email === this.email);
        // if (userExists) {
        //     return res.status(400).json({status: 'error', error: 'User already exists'});
        // }

        this.stored.push({
            challenge: makeCredChallenge.challenge,
            email
        });

        return res.status(200).json(makeCredChallenge);
    }

    async response(req: Request, res: Response) {
        if (
            !req.body?.id ||
            !req.body?.rawId ||
            !req.body?.response ||
            !req.body?.type ||
            req.body?.type !== 'public-key'
        ) {
            return res.status(400).json({
                status: 'failed',
                message: 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!',
            });
        }

        const {response: credential} = req.body;
        const clientDataJSON = base64url.decode(credential.clientDataJSON);
        const decodedClientData = JSON.parse(clientDataJSON);

        if (decodedClientData.origin !== "https://webauthn-beta.vercel.app") {
            return res.status(400).json({status: 'failed', message: 'Invalid origin'});
        }

        if (decodedClientData.type !== "webauthn.create") {
            return res.status(400).json({status: 'failed', message: 'Invalid clientData.type'});
        }

        const decodedChallenge = new Buffer(decodedClientData.challenge, 'base64').toString('ascii');
        const user = this.stored.find((user: any) => user.email === this.email);

        if (decodedChallenge !== user.challenge) {
            return res.status(400).json({status: 'failed', message: 'Invalid challenge'});
        }

        let result;
        if (credential.attestationObject !== undefined) {
            result = await this.userService.verifyAuthenticatorAttestationResponse(credential);

            if (result.verified) {
                Object.assign(user, {
                    // @ts-ignore
                    authenticators: [{...result.authrInfo}]
                });
                user.registered = true;
                // user.save();
            }
        } else if (credential.response.authenticatorData !== undefined) {
            /* This is get assertion */
            result = await this.userService.verifyAuthenticatorAssertionResponse(credential, user.authenticators);
        } else {
            return res.json({
                'status': 'failed',
                'message': 'Can not determine type of response!'
            });
        }

        if (result.verified) {
            // req.session.loggedIn = true;
            return res.json({'status': 'ok'});
        } else {
            return res.json({
                'status': 'failed',
                'message': 'Can not authenticate signature!'
            });
        }
    }
}

export default UserController;
