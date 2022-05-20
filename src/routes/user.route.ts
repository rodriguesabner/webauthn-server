import {Router} from "express";
import UserController from "../controller/user.controller";

class UserRoute {
    public router: Router;
    private controller: UserController;

    constructor() {
        this.controller = new UserController();
        this.router = Router();
        this.routes();
    }

    routes() {
        this.router.post("/register", this.controller.register.bind(this.controller));
        this.router.post("/response", this.controller.response.bind(this.controller));
        this.router.post("/login", this.controller.login.bind(this.controller));
        this.router.post("/authResponse", this.controller.authResponse.bind(this.controller));
    }
}

export default UserRoute;
