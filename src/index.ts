import {config} from "dotenv";
config();

import {createServer} from "http";
import Server from "./server";

const PORT = process.env.PORT || 8002;
const http = createServer(Server);

http.listen(PORT, async () => {
    console.log("Server listening on http://localhost:" + PORT);
});
