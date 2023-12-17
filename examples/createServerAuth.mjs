import { createProxyServer } from "../dist/index.js";

const server = createProxyServer({
  authenticate: (username, password) =>
    username === "foo" && password === "bar",
});

// start listening!
server.listen(1080);
