import { createProxyServer } from '../dist/index.js';
import dns from 'dns';

const server = createProxyServer({
	filter: (destinationAddress, destinationPort, socket) =>
		new Promise((resolve, reject) => {
			console.log('Attempting to connect to...');
			console.log({ address: destinationAddress, port: destinationPort });
			console.log();
			console.log('Inbound origin of request is...');
			console.log({ address: socket.remoteAddress, port: socket.remotePort });

			return dns.reverse(destinationAddress, (err, hostnames) => {
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
