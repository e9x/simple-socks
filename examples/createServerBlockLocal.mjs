import { createProxyServer } from "../dist/index.js";
import ipaddr from "ipaddr.js";
import { resolve } from "node:dns/promises";

const server = createProxyServer({
  async filter(destinationPort, destinationAddress, socket) {
    const addresses = ipaddr.isValid(destinationAddress)
      ? [destinationAddress]
      : await resolve(destinationAddress);

    const ip = ipaddr.parse(addresses[0]);

    if (ip.range() !== "unicast") {
      console.log(
        socket.remoteAddress,
        "just attempted to connect to non-unicast (local) IP:",
        ip.toString()
      );

      throw undefined;
    }
  },
});

// start listening!
server.listen(1080);
