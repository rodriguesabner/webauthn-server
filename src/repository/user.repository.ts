import {UserModel} from "../model/user.model";

class UserRepository {
    constructor() {
    }

    findUserByChallenge(challenge: string) {
        return UserModel.findOne({challenge: challenge});
    }

    async findUserByUnique({query}: { query: string }) {
        return UserModel.findOne({name: query});
    }

    async setCredentialsUserByChallenge({challenge, credentials}: { challenge: string, credentials: any }) {
        await UserModel.updateOne(
            {challenge: challenge},
            {$set: {credentials: credentials}}
        );
    }

}

export default UserRepository;
