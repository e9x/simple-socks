import { createProxyServer } from "../dist/index.js";

const server = createProxyServer();

// start listening!
server.listen(1080);
