import { createProxyServer } from '../dist/index.js';
import ipaddr from 'ipaddr.js';
import { reverse } from 'node:dns';

const server = createProxyServer({
	filter: (destinationPort, destinationAddress, socket) =>
		new Promise((resolve, reject) => {
			console.log('Attempting to connect to...');
			console.log({ address: destinationAddress, port: destinationPort });
			console.log();
			console.log('Inbound origin of request is...');
			console.log({ address: socket.remoteAddress, port: socket.remotePort });

			const checkHostname = (hostname) => {
				if (!/github/.test(hostname)) {
					console.log(
						'Not allowing connection to %s:%s',
						destinationAddress,
						destinationPort
					);

					return reject();
				}

				return resolve();
			};

			// prevent looking up ip address
			if (!ipaddr.isValid(destinationAddress))
				return checkHostname(destinationAddress);

			return reverse(destinationAddress, (err, hostnames) => {
				if (
					err ||
					!hostnames ||
					!hostnames.length ||
					!/github/.test(hostnames[0])
				) {
					console.log(
						'Not allowing connection to %s:%s',
						destinationAddress,
						destinationPort
					);

					return reject();
				}

				return resolve();
			});
		}),
});

// start listening!
server.listen(1080);
