import express from "express";
import cors from "cors";
import Routes from "./routes";
import session from "express-session";
import useragent from 'express-useragent';

class Server {
    public app: express.Application;

    constructor() {
        this.app = express();

        this.config();
        this.routes();
    }

    config() {
        this.app.use(useragent.express());
        this.app.use(express.json());
        this.app.use(express.urlencoded({extended: true}));
        this.app.use(cors({
            //multiple origins
            origin: ["http://localhost:3000", "https://webauthn-beta.vercel.app"],
            credentials: true
        }));
        this.app.set('trust proxy', 1) // trust first proxy
        this.app.use(session({
            name: "session_name",
            secret: process.env.SECRET || 'secret',
            resave: false,
            saveUninitialized: false,
            proxy: true,
            cookie: {
                secure: process.env.NODE_ENV !== 'localhost',
                path: '/',
                sameSite: 'strict',
                httpOnly: true,
                maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
            }
        }))
    }

    routes() {
        this.app.use("", new Routes().app);
    }

}

export default new Server().app;
