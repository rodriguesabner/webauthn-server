import {createServer} from "http";
import localtunnel from "localtunnel";
import Server from "./server";

const PORT = 8002 || process.env.PORT;
const http = createServer(Server);

const server = http.listen(PORT, async () => {
    const tunnel = await localtunnel({port: PORT, subdomain: "zoox-auth"});

    console.log("Server listening on http://localhost:" + PORT);
    // @ts-ignore
    console.log("Tunnel:https://" + tunnel.clientId + ".loca.lt");

    tunnel.on("close", () => {
        console.log("Tunnel closed");
    });

    process.on("exit", () => {
        tunnel.close();
    });
});

export {
    server
}
