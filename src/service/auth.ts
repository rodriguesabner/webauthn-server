import admin from "firebase-admin";
import credentials from "../common/credentials.json";

const firebase = admin;
admin.initializeApp({
    // @ts-ignore
    credential: admin.credential.cert(credentials),
    databaseURL: "https://webauthn-6d12c-default-rtdb.firebaseio.com"
});

const ret = {
    db: firebase.database(),
    auth: firebase.auth(),
    storage: firebase.storage(),
    messaging: firebase.messaging(),
}

export default ret;
