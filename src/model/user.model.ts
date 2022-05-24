import {model, Schema} from "mongoose";

const UserSchema = new Schema({
    user_id: {
        type: String,
    },
    name: {
        type: String,
    },
    displayName: {
        type: String,
    },
    challenge: {
        type: String,
    },
    credentials: {
        type: Array,
    },
});

const UserModel = model("Users", UserSchema);

export {
    UserModel
};
