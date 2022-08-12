import { createProxyServer } from '../dist/index.js';
import { SocksClient } from 'socks';

const server = createProxyServer({
	async connect(port, host) {
		// connect to TOR socks proxy
		const { socket } = await SocksClient.createConnection({
			proxy: {
				host: '127.0.0.1',
				port: 9050, // TOR daemon
				type: 5,
			},
			command: 'connect',
			destination: {
				port,
				host,
			},
		});

		return socket;
	},
});

// start listening!
server.listen(1080);
