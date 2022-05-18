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
            return res.status(404).send('User does not exist');

        const getAssertion: any = serverGetAssertion(user);
        getAssertion.status = 'ok';

        return res.status(200).json(getAssertion);
    }

    async register(req: Request, res: Response) {
        const {email} = req.body;
        if (!email)
            return res.status(400).send('Missing email field');

        let credentials = this.userService.generateCredentials();

        let userExists = this.stored.find((user: any) => user.email === this.email);
        if (userExists) {
            userExists.challenge = credentials.challenge;
            userExists.email = credentials.user.displayName;
        } else {
            this.stored.push({
                challenge: credentials.challenge,
                email: credentials.user.displayName,
            });
        }

        // @ts-ignore
        req.session.challenge = credentials.challenge;
        // @ts-ignore
        req.session.email = credentials.user.email;

        return res.status(200).json(credentials);
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

        const user = this.stored.find((user: any) => user.email === this.email);

        if (decodedClientData.challenge !== user.challenge) {
            return res.status(400).json({status: 'failed', message: 'Invalid challenge'});
        }

        if(!['webauthn.get', 'webauthn.create'].includes(decodedClientData.type)) {
            return res.status(400).json({'status': 'failed', 'message': 'Can not determine type of response!'});
        }

        if (decodedClientData.type === "webauthn.get") {
            const ret = this.userService.verifyAuthenticatorAssertionResponse(req.body, user.authenticators);
            console.log(ret);
        } else {
            const result = await this.userService.verifyAuthenticatorAttestationResponse(credential);

            if (result.verified) {
                Object.assign(user, {
                    authenticators: [{...result.authrInfo}]
                });
                user.registered = true;
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
}

export default UserController;
