import { createProxyServer } from '../dist/index.js';
import dns from 'dns/promises';
import ipaddr from 'ipaddr.js';

const server = createProxyServer({
	async filter(destinationPort, destinationAddress, socket) {
		const addresses = await dns.resolve(destinationAddress);

		const ip = ipaddr.parse(addresses[0]);

		if (ip.range() !== 'unicast') {
			console.log(
				socket.remoteAddress,
				'just attempted to connect to non-unicast (local) IP:',
				ip.toString()
			);

			throw undefined;
		}
	},
});

// start listening!
server.listen(1080);
