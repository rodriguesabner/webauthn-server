import {Request, Response} from "express";
import UserService from "../service/user.service";
import UserRepository from "../repository/user.repository";

class UserController {
    private userService: UserService;
    private userRepository: UserRepository;

    constructor() {
        this.userService = new UserService();
        this.userRepository = new UserRepository();
    }

    async getCredentials(req: Request, res: Response) {
        const {name}: any = req.query;

        try {
            const existentUser = await this.userService.getCredentials(name);
            return res.status(200).json(existentUser);
        } catch (e) {
            return res.status(404).json({message: 'User not found'});
        }
    }

    async login(req: Request, res: Response) {
        const requestParams = req.body;

        if (!requestParams.name)
            return res.status(400).send('Missing name field');

        try {
            const ret = await this.userService.authenticate(requestParams);
            return res.status(200).json(ret);
        } catch (e: any) {
            return res.status(400).send(e.message);
        }
    }

    async register(req: Request, res: Response) {
        const requestParams = req.body;

        if (!requestParams.name || !requestParams.displayName)
            return res.status(400).send('Missing name field');

        try {
            Object.assign(requestParams, {userAgent: req.useragent, origin: req.headers.origin});
            const ret = await this.userService.register(requestParams);
            return res.status(200).json(ret);
        } catch (e: any) {
            return res.status(400).send(e.message);
        }
    }

    async response(req: Request, res: Response) {
        const credential = req.body;
        if (!credential.response)
            return res.status(400).send('Missing response field');

        try {
            const ret = await this.userService.registerResponse(credential, req.useragent, req.headers.origin);
            return res.status(200).json(ret);
        } catch (e: any) {
            return res.status(400).send(e.message);
        }
    }

    async authResponse(req: Request, res: Response) {
        const credential = req.body;
        if (!credential.response) return res.status(400).json({error: 'response field is required'});

        try {
            // @ts-ignore
            const ret = await this.userService.authenticateResponse(credential, req.headers.origin);
            return res.status(200).json(ret);
        } catch (e: any) {
            return res.status(400).send(e.message);
        }

    }

}

export default UserController;
