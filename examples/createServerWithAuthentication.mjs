import { createProxyServer } from '../dist/index.js';

const server = createProxyServer({
	authenticate: (username, password) =>
		new Promise((resolve, reject) => {
			// verify username/password
			if (username !== 'foo' || password !== 'bar') {
				// respond with auth failure (can be any error)
				return reject();
			}

			// return successful authentication
			return resolve();
		}),
});

// start listening!
server.listen(1080);
