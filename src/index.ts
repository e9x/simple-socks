import {
	RFC_1928_ATYP,
	RFC_1928_COMMANDS,
	RFC_1928_METHODS,
	RFC_1928_REPLIES,
	RFC_1928_VERSION,
	RFC_1929_REPLIES,
	RFC_1929_VERSION,
} from './constants.js';
import binary from 'binary';
import net from 'net';

const LENGTH_RFC_1928_ATYP = 4;

/**
 *
 * @param socket Socket that emits the `connect` event upon connection, and the `error` event upon failure. Socket must be in the connecting state and not already connected.
 * @returns
 */
export const waitForConnect = <T extends net.Socket>(socket: T) =>
	new Promise<void>((resolve, reject) => {
		const connectHandler = () => {
			socket.removeListener('error', errorHandler);
			resolve();
		};

		const errorHandler = (err: unknown) => {
			socket.removeListener('connect', connectHandler);
			reject(err);
		};

		socket.once('error', errorHandler);
		socket.once('connect', connectHandler);
	});

interface ProxyServerOptions {
	/**
	 * @returns A resolved promise indicates the credentials are correct and the proxy will proceed. A rejected promise indicates the credentials are incorrect and will result in the connection being closed.
	 */
	authenticate?(
		username: string,
		password: string,
		socket: net.Socket
	): Promise<void>;
	/**
	 * Determine if the connection to the destination is allowed.
	 * @returns A resolved promise indicates the connection is allowed and the proxy will proceed to the authentication phase. A rejected promise indicates the connection conditions are not allowed and will result in the connection being closed.
	 */
	filter?(port: number, host: string, socket: net.Socket): Promise<void>;
	/**
	 * This is intended for slightly higher APIs.
	 * What will work:
	 * - Chaining socks proxies (Server connects to internal socks proxy eg Tor)
	 * - Redirecting to more secure services (80 -> 443, wrapped in tls.connect)
	 * What will not work:
	 * - Wrapping sockets in TLS to services that don't support TLS
	 * @returns You must bind the `connect` and `error` events to resolve/reject. Once the promise is resolved, it is assumed that the socket is connected. Returning a normal socket will assume it is not connected already. If your API provides the `connect` and `error` event, you can use our built-in promise wrapper `waitForConnect`.
	 */
	connect(port: number, host: string, socket: net.Socket): Promise<net.Socket>;
}

function isConnectErr(err: { code?: string } | void): err is { code: string } {
	return err && typeof err.code === 'string';
}

/**
 * The following RFCs may be useful as background:
 *
 * https://www.ietf.org/rfc/rfc1928.txt - NO_AUTH SOCKS5
 * https://www.ietf.org/rfc/rfc1929.txt - USERNAME/PASSWORD SOCKS5
 *
 **/
function addProxyListeners(server: net.Server, options: ProxyServerOptions) {
	const activeSessions: net.Socket[] = [];

	server.on('connection', (socket) => {
		// eslint-disable-next-line @typescript-eslint/no-empty-function
		socket.on('error', () => {});

		/**
		 * +----+------+----------+------+----------+
		 * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		 * +----+------+----------+------+----------+
		 * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		 * +----+------+----------+------+----------+
		 **/
		const authenticate = (buffer: Buffer) => {
			binary
				.stream(buffer)
				.word8('ver')
				.word8('ulen')
				.buffer('uname', 'ulen')
				.word8('plen')
				.buffer('passwd', 'plen')
				.tap(async (args) => {
					// capture the raw buffer
					args.requestBuffer = buffer;

					// verify version is appropriate
					if (args.ver !== RFC_1929_VERSION) {
						return end(RFC_1929_REPLIES.GENERAL_FAILURE, args);
					}

					// perform authentication
					// options.authenticate is guaranteed to exist, connections providing authentication when options.authenticate doesnt exist will be terminated
					try {
						await options.authenticate(
							args.uname.toString(),
							args.passwd.toString(),
							socket
						);

						// respond with success...
						const responseBuffer = Buffer.allocUnsafe(2);
						responseBuffer[0] = RFC_1929_VERSION;
						responseBuffer[1] = RFC_1929_REPLIES.SUCCEEDED;

						// respond then listen for cmd and dst info
						socket.write(responseBuffer, () => {
							// now listen for more details
							socket.once('data', connect);
						});
					} catch (err) {
						// respond with auth failure
						end(RFC_1929_REPLIES.GENERAL_FAILURE, args);
					}
				});
		};

		/**
		 * +----+-----+-------+------+----------+----------+
		 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		 * +----+-----+-------+------+----------+----------+
		 * | 1  |  1  | X'00' |  1   | Variable |    2     |
		 * +----+-----+-------+------+----------+----------+
		 **/
		const connect = (buffer: Buffer) => {
			const binaryStream = binary.stream(buffer);

			binaryStream
				.word8('ver')
				.word8('cmd')
				.word8('rsv')
				.word8('atyp')
				.tap((args) => {
					// capture the raw buffer
					args.requestBuffer = buffer;

					// verify version is appropriate
					if (args.ver !== RFC_1928_VERSION) {
						return end(RFC_1928_REPLIES.GENERAL_FAILURE, args);
					}

					// append socket to active sessions
					activeSessions.push(socket);

					// create dst
					args.dst = {};

					// ipv4
					if (args.atyp === RFC_1928_ATYP.IPV4) {
						binaryStream
							.buffer('addr.buf', LENGTH_RFC_1928_ATYP)
							.tap((args) => {
								args.dst.addr = [].slice.call(args.addr.buf).join('.');
							});

						// domain name
					} else if (args.atyp === RFC_1928_ATYP.DOMAINNAME) {
						binaryStream
							.word8('addr.size')
							.buffer('addr.buf', 'addr.size')
							.tap((args) => {
								args.dst.addr = args.addr.buf.toString();
							});

						// ipv6
					} else if (args.atyp === RFC_1928_ATYP.IPV6) {
						binaryStream
							.word32be('addr.a')
							.word32be('addr.b')
							.word32be('addr.c')
							.word32be('addr.d')
							.tap((args) => {
								args.dst.addr = [];

								// extract the parts of the ipv6 address
								['a', 'b', 'c', 'd'].forEach((part) => {
									const x: number = args.addr[part];

									// convert DWORD to two WORD values and append
									/* eslint no-magic-numbers : 0 */
									args.dst.addr.push((x >>> 16).toString(16));
									args.dst.addr.push((x & 0xffff).toString(16));
								});

								// format ipv6 address as string
								args.dst.addr = args.dst.addr.join(':');
							});

						// unsupported address type
					} else {
						return end(RFC_1928_REPLIES.ADDRESS_TYPE_NOT_SUPPORTED, args);
					}
				})
				.word16bu('dst.port')
				.tap(async (args) => {
					if (args.cmd === RFC_1928_COMMANDS.CONNECT) {
						// perform connection
						try {
							if (options.filter)
								await options.filter(
									// destination
									args.dst.addr,
									args.dst.port,
									socket
								);

							try {
								const destination = await options.connect(
									args.dst.port,
									args.dst.addr,
									socket
								);

								// prepare a success response
								const responseBuffer = Buffer.alloc(args.requestBuffer.length);
								args.requestBuffer.copy(responseBuffer);
								responseBuffer[1] = RFC_1928_REPLIES.SUCCEEDED;

								// write acknowledgement to client...
								socket.write(responseBuffer, () => {
									// listen for data bi-directionally
									destination.pipe(socket);
									socket.pipe(destination);
								});
							} catch (err) {
								if (isConnectErr(err)) {
									if (err.code === 'EADDRNOTAVAIL')
										return end(RFC_1928_REPLIES.HOST_UNREACHABLE, args);
									else if (err.code === 'ECONNREFUSED')
										return end(RFC_1928_REPLIES.CONNECTION_REFUSED, args);
								}

								return end(RFC_1928_REPLIES.NETWORK_UNREACHABLE, args);
							}
						} catch (err) {
							// respond with failure
							return end(RFC_1928_REPLIES.CONNECTION_NOT_ALLOWED, args);
						}
					} else {
						// bind and udp associate commands
						return end(RFC_1928_REPLIES.SUCCEEDED, args);
					}
				});
		};

		/**
		 * +----+-----+-------+------+----------+----------+
		 * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		 * +----+-----+-------+------+----------+----------+
		 * | 1  |  1  | X'00' |  1   | Variable |    2     |
		 * +----+-----+-------+------+----------+----------+
		 *
		 * @param response - a buffer representing the response
		 * @param args to supply to the proxy end event
		 * @returns
		 **/
		const end = (response: number, args: { requestBuffer?: Buffer }) => {
			// either use the raw buffer (if available) or create a new one
			const responseBuffer = args.requestBuffer || Buffer.allocUnsafe(2);

			if (!args.requestBuffer) {
				responseBuffer[0] = RFC_1928_VERSION;
			}

			responseBuffer[1] = response;

			// respond then end the connection
			try {
				socket.end(responseBuffer);
			} catch (ex) {
				socket.destroy();
			}
		};

		/**
		 * +----+----------+----------+
		 * |VER | NMETHODS | METHODS  |
		 * +----+----------+----------+
		 * | 1  |    1     | 1 to 255 |
		 * +----+----------+----------+
		 *
		 * @param {Buffer} buffer - a buffer
		 * @returns {undefined}
		 **/
		const handshake = (buffer) => {
			binary
				.stream(buffer)
				.word8('ver')
				.word8('nmethods')
				.buffer('methods', 'nmethods')
				.tap((args) => {
					// verify version is appropriate
					if (args.ver !== RFC_1928_VERSION) {
						return end(RFC_1928_REPLIES.GENERAL_FAILURE, args);
					}

					// convert methods buffer to an array
					const acceptedMethods = [].slice
						.call(args.methods)
						.reduce((methods, method) => {
							methods[method] = true;
							return methods;
						}, {});
					const basicAuth = typeof options.authenticate === 'function';
					let next = connect;
					const noAuth =
							!basicAuth &&
							typeof acceptedMethods[0] !== 'undefined' &&
							acceptedMethods[0],
						responseBuffer = Buffer.allocUnsafe(2);

					// form response Buffer
					responseBuffer[0] = RFC_1928_VERSION;
					responseBuffer[1] = RFC_1928_METHODS.NO_AUTHENTICATION_REQUIRED;

					// check for basic auth configuration
					if (basicAuth) {
						responseBuffer[1] = RFC_1928_METHODS.BASIC_AUTHENTICATION;
						next = authenticate;

						// if NO AUTHENTICATION REQUIRED and
					} else if (!basicAuth && noAuth) {
						responseBuffer[1] = RFC_1928_METHODS.NO_AUTHENTICATION_REQUIRED;
						next = connect;

						// basic auth callback not provided and no auth is not supported
					} else {
						return end(RFC_1928_METHODS.NO_ACCEPTABLE_METHODS, args);
					}

					// respond then listen for cmd and dst info
					socket.write(responseBuffer, () => {
						// now listen for more details
						socket.once('data', next);
					});
				});
		};

		// capture the client handshake
		socket.once('data', handshake);

		// capture socket closure
		socket.once('end', () => {
			// remove the session from currently the active sessions list
			activeSessions.splice(activeSessions.indexOf(socket), 1);
		});
	});
}

export function createProxyServer(
	partialOptions: Partial<ProxyServerOptions> = {}
): net.Server {
	// stub connect
	if (!partialOptions.connect)
		partialOptions.connect = async (port, host) => {
			const socket = net.connect(port, host);
			// let the server catch any errors
			await waitForConnect(socket);
			return socket;
		};

	const server = net.createServer();

	addProxyListeners(server, <ProxyServerOptions>partialOptions);

	return server;
}
