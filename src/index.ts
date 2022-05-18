import {createServer} from "http";
import Server from "./server";

const PORT = 8002 || process.env.PORT;
const http = createServer(Server);

const server = http.listen(PORT, async () => {
    console.log("Server listening on http://localhost:" + PORT);
});

export {
    server
}
