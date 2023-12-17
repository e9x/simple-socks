import { createProxyServer } from "../dist/index.js";
import ipaddr from "ipaddr.js";
import { reverse } from "node:dns/promises";

const server = createProxyServer({
  filter: (destinationPort, destinationAddress, socket) => {
    console.log("Attempting to connect to...");
    console.log({ address: destinationAddress, port: destinationPort });
    console.log();
    console.log("Inbound origin of request is...");
    console.log({ address: socket.remoteAddress, port: socket.remotePort });

    const checkHostname = (hostname) => {
      if (!/github/.test(hostname)) {
        console.log(
          "Not allowing connection to %s:%s",
          destinationAddress,
          destinationPort
        );

        return false;
      }

      return true;
    };

    // prevent looking up ip address
    if (!ipaddr.isValid(destinationAddress))
      return checkHostname(destinationAddress);

    return reverse(destinationAddress).then((hostnames) => {
      if (!hostnames.some((host) => /github/.test(host))) {
        console.log(
          "Not allowing connection to %s:%s",
          destinationAddress,
          destinationPort
        );

        return false;
      }

      return true;
    });
  },
});

// start listening!
server.listen(1080);
