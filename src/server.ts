import express from "express";
import cors from "cors";
import Routes from "./routes";
import cookieSession from "cookie-session";
import cookieParser from "cookie-parser";
import {randomHex32String} from "./common/helper";

class Server {
    public app: express.Application;

    constructor() {
        this.app = express();

        this.config();
        this.routes();
    }

    config() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({extended: true}));
        this.app.use(cors({origin: "*"}));
        this.app.use(
            cookieSession({
                name: "session",
                keys: [randomHex32String()],
                maxAge: 24 * 60 * 60 * 1000,
            })
        );
        this.app.use(cookieParser());
    }

    routes() {
        this.app.use("", new Routes().app);
    }

}

export default new Server().app;
