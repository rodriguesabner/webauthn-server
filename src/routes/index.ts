import express, {Application} from "express";
import UserRoute from "./user.route";

class Routes {
    public app: Application;

    constructor() {
        this.app = express();
        this.routes();
    }

    routes() {
        this.app.use("/user", new UserRoute().router);
    }
}

export default Routes;
