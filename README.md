# Simple Socks Server

Creates a simple SOCKS5 server and gives you control over the flow (filter, auth, protocol).

This is a clone of https://github.com/brozeph/simple-socks. This project would not be possible without their contributions to simple-socks.

<a href="https://www.npmjs.com/package/@e9x/simple-socks"><img src="https://img.shields.io/npm/v/@e9x/simple-socks.svg?maxAge=3600" alt="npm version" /></a>

## Installation

```
npm install @e9x/simple-socks
```

## Example Usage

In the [examples](examples/) folder exists two examples, one that requires no authentication and one that requires username/password authentication. Below is an example with no authentication:

```js
import { createProxyServer } from '@e9x/simple-socks';

const server = createProxyServer();

server.listen(1080);
```

### Running The Examples

#### No Authentication

For a SOCKS5 server that does not require authentication, look at [examples/createServer.mjs](examples/createServer.js):

```bash
node examples/createServer.mjs
```

In a separate terminal window:

```bash
curl http://www.google.com --socks5 127.0.0.1:1080
```

#### Username/Password Authentication

For a SOCKS5 server that requires username/password authentication, look at [examples/createServerWithAuthentication.mjs](examples/createServerWithAuthentication.mjs):

```bash
node examples/createServerWithAuthentication.mjs
```

In a separate terminal window:

```bash
curl http://www.google.com --socks5 127.0.0.1:1080 --proxy-user foo:bar
```

#### Connection Filter

For a SOCKS5 server that can perform either origin or destination (or both!) address filtering, look at [examples/createServerFilter.mjs](examples/createServerFilter.mjs):

```bash
node examples/createServerFilter.mjs
```

In a separate terminal window:

```bash
curl http://www.github.com --socks5 127.0.0.1:1080 # allowed
curl http://www.google.com --socks5 127.0.0.1:1080 # denied
```

#### Chained Socks Proxies

The underlying API to connect to the destination is exposed to allow for flexibility. As a result, you can use slightly higher level APIs to establish a connection to the destination. For a SOCKS5 server will connect to a locally hosted TOR socks proxy, look at [examples/createServerConnect.mjs](examples/createServerConnect.mjs):

```bash
node examples/createServerConnect.mjs
```

In a separate terminal window:

```bash
curl https://myip.wtf/json --socks5 127.0.0.1:1080
```

```json
{
    "YourF****ingTorExit": true,
}
```

## Methods

### createProxyServer

Factory method that creates an instance of a SOCKS5 proxy server:

```js
import { createProxyServer } from '@e9x/simple-socks';

const server = createProxyServer();

server.listen(1080, '0.0.0.0', function () {
	console.log('SOCKS5 proxy server started on 0.0.0.0:1080');
});
```

This method accepts an optional `options` argument:

- `options.authentication` - A callback for authentication
- `options.filter` - A callback for connection filtering
- `options.connect` - A callback for low-level connecting

Unlike simple-socks, the callbacks are based on modern promises.

#### authentication

To make the socks5 server require username/password authentication, supply a function callback in the options as follows:

```js
import { createProxyServer } from '@e9x/simple-socks';

const server = createProxyServer({
	authenticate: (username, password, socket) => new Promise((resolve, reject) => {
		if (username === 'foo' && password === 'bar') {
			return resolve();
		}

		return reject();
	}),
});

// begin listening and require user/pass authentication
server.listen(1080);
```

The `authenticate` callback accepts three arguments:

- username - username of the proxy user
- password - password of the proxy user
- socket - the socket for the client connection

You must return a promise. The promise resolving indicates the credentials were accepted. The promise rejecting indicates the credentials were rejected.

#### filter

Allows you to filter incoming connections, based on either origin and/or destination.

```js
import { createProxyServer } from '@e9x/simple-socks';

const server = createProxyServer({
	filter: (destination, origin) => new Promise((resolve, reject) => {
		if (origin.address === '127.0.0.1') {
			console.log('denying access from %s:%s', origin.address, origin.port);

			return reject();
		}

		if (destination.address === '10.0.0.1') {
			console.log('denying access to %s:%s', remote.address, remote.port);

			return reject();
		}

		return resolve();
	}),
});
```

The `filter` callback accepts three arguments:

- port - the TCP port of the destination server
- address - the TCP address of the destination server
- socket - the socket for the client connection

For an example, see [examples/createServerFilter.js](examples/createServerFilter.js).

You must return a promise. The promise resolving indicates the connection was accepted. The promsie rejecting indicates the connection was rejected.

#### connect

Allows you to control the flow of connecting to the remote.

```js
import { createProxyServer } from '@e9x/simple-socks';
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
```

The `connect` callback accepts three arguments:

- port - the TCP port of the destination server
- address - the TCP address of the destination server
- socket - the socket for the client connection

For an example, see [examples/createServerConnect.js](examples/createServerFilter.js).

You must return a promise. The promise resolving indicates the connection was accepted **and is CONNECTED**. The promsie rejecting indicates the connection was rejected **and was NOT connected**. You can wrap an unconnected socket in [waitForConnect](#waitforconnect) to make it compatible with this callback.

### waitForConnect

Method that will wait for a socket to connect to help use unconnected sockets as the resolution for [connect](#connect):

```js
import { createProxyServer, waitForConnect } from '@e9x/simple-socks';
import { connect } from 'net';

const server = createProxyServer({
	async connect(port, host) {
		// create unconnected socket
		const socket = connect(port, host);

		await waitForConnect(socket);

		return socket;
	},
});
```

The `waitForConnect` method accepts one argument:

- socket - the socket to the destination

The socket must not already be connected when calling this method. If it is, return the socket instead of calling this method. This method will throw an error if the socket could not connect. This error should be caught in the stack that called options.connect. You should not catch this error and return a different one because it contains an error code that is used to determine how the socket was ended.

## Events

Unlike simple-socks, events have been removed due to the unlikeliness of them being used and their nature of wasting resources. Specifically the proxyData event is the culprit of poor speeds. It may be argued the events being fired constantly are a waste of resources too. Use the hooks provided in options instead.