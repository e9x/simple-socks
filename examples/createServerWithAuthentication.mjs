import { createProxyServer } from "../dist/index.js";

const server = createProxyServer({
  authenticate: (username, password) => {
    // verify username/password
    if (username !== "foo" || password !== "bar") {
      // respond with auth failure
      return false;
    }

    // return successful authentication
    return true;
  },
});

// start listening!
server.listen(1080);
