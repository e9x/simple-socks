import {
  LENGTH_RFC_1928_ATYP,
  RFC_1928_ATYP,
  RFC_1928_COMMANDS,
  RFC_1928_METHODS,
  RFC_1928_REPLIES,
  RFC_1928_VERSION,
  RFC_1929_REPLIES,
  RFC_1929_VERSION,
} from "./constants.js";
import { stream } from "binary";
import type { Socket, Server } from "node:net";
import { connect, createServer } from "node:net";

/**
 *
 * @param socket Socket that emits the `connect` event upon connection, and the `error` event upon failure. Socket must be in the connecting state and not already connected. The promise will resolve once the socket is connected and will reject if an error occurs before a connection is established.
 */
export const waitForConnect = <T extends Socket>(socket: T) =>
  new Promise<void>((resolve, reject) => {
    const connectHandler = () => {
      socket.removeListener("error", errorHandler);
      resolve();
    };

    const errorHandler = (err: unknown) => {
      socket.removeListener("connect", connectHandler);
      reject(err);
    };

    socket.once("error", errorHandler);
    socket.once("connect", connectHandler);
  });

export interface ProxyServerOptions {
  /**
   * Determine if the connection to the destination is allowed.
   * @returns If the return resolves to true, proxy will begin to authenticate. Otherwise, the connection conditions are not allowed and the connection will be ended.
   */
  filter?(
    port: number,
    host: string,
    socket: Socket,
  ): Promise<boolean> | boolean;
  /**
   * @returns If the return resolves to true, the proxy will proceed. Otherwise, the credentials are incorrect and the connection will be ended.
   */
  authenticate?(
    username: string,
    password: string,
    socket: Socket,
  ): Promise<boolean> | boolean;
  /**
   * This is intended for slightly higher APIs.
   * What will work:
   * - Chaining socks proxies (Server connects to internal socks proxy eg Tor)
   * - Redirecting to more secure services (80 -> 443, wrapped in tls.connect)
   * What will not work:
   * - Wrapping sockets in TLS to services that don't support TLS
   * @returns You must bind the `connect` and `error` events to resolve/reject. Once the promise is resolved, it is assumed that the socket is connected. Returning a normal socket will assume it is not connected already.
   *
   * If your API provides the `connect` and `error` event, you can use our built-in promise wrapper `waitForConnect`.
   */
  connect(port: number, host: string, socket: Socket): Promise<Socket> | Socket;
}

function isErrCode(err: unknown): err is { code: string } {
  return (
    typeof err === "object" &&
    err !== null &&
    typeof (err as { code?: unknown }).code === "string"
  );
}

/**
 * The following RFCs may be useful as background:
 *
 * https://www.ietf.org/rfc/rfc1928.txt - NO_AUTH SOCKS5
 * https://www.ietf.org/rfc/rfc1929.txt - USERNAME/PASSWORD SOCKS5
 *
 **/
function addProxyListeners(server: Server, options: ProxyServerOptions) {
  const activeSessions: Socket[] = [];

  server.on("connection", (socket) => {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    socket.on("error", () => {});

    /**
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     **/
    const authenticate = (buffer: Buffer) => {
      stream<{
        ver?: any;
        uname?: any;
        passwd?: any;
      }>(buffer)
        .word8("ver")
        .word8("ulen")
        .buffer("uname", "ulen")
        .word8("plen")
        .buffer("passwd", "plen")
        .tap(async (args) => {
          // verify version is appropriate
          if (args.ver !== RFC_1929_VERSION) {
            return end(authenticateReply(RFC_1929_REPLIES.GENERAL_FAILURE));
          }

          // perform authentication
          // options.authenticate is guaranteed to exist, connections providing authentication when options.authenticate doesnt exist will be terminated
          const auth = await options.authenticate!(
            args.uname.toString(),
            args.passwd.toString(),
            socket,
          );

          if (auth) {
            // respond with success...
            const responseBuffer = authenticateReply(
              RFC_1929_REPLIES.SUCCEEDED,
            );

            // respond then listen for cmd and dst info
            socket.write(responseBuffer, () => {
              // now listen for more details
              socket.once("data", connect);
            });
          } else {
            // respond with auth failure
            end(authenticateReply(RFC_1929_REPLIES.GENERAL_FAILURE));
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
      const binaryStream = stream<{
        cmd: number;
        ver: number;
        atyp: number;
        addr: { buf: Buffer; a: number; b: number; c: number; d: number };
        // manually set:
        dst: { addr: string; port: number };
      }>(buffer);

      binaryStream
        .word8("ver")
        .word8("cmd")
        .word8("rsv")
        .word8("atyp")
        .tap((args) => {
          // verify version is appropriate
          if (args.ver !== RFC_1928_VERSION) {
            return endConnect(RFC_1928_REPLIES.GENERAL_FAILURE, buffer);
          }

          // append socket to active sessions
          activeSessions.push(socket);

          let addr = "";

          // ipv4
          if (args.atyp === RFC_1928_ATYP.IPV4) {
            binaryStream
              .buffer("addr.buf", LENGTH_RFC_1928_ATYP)
              .tap((args) => {
                addr = [].slice.call(args.addr.buf).join(".");
              });

            // domain name
          } else if (args.atyp === RFC_1928_ATYP.DOMAINNAME) {
            binaryStream
              .word8("addr.size")
              .buffer("addr.buf", "addr.size")
              .tap((args) => {
                addr = args.addr.buf.toString();
              });

            // ipv6
          } else if (args.atyp === RFC_1928_ATYP.IPV6) {
            binaryStream
              .word32be("addr.a")
              .word32be("addr.b")
              .word32be("addr.c")
              .word32be("addr.d")
              .tap((args) => {
                const parts: string[] = [];

                // extract the parts of the ipv6 address
                for (const part of ["a", "b", "c", "d"]) {
                  const x: number = args.addr[part as "a" | "b" | "c" | "d"];

                  // convert DWORD to two WORD values and append
                  parts.push((x >>> 16).toString(16));
                  parts.push((x & 0xffff).toString(16));
                }

                // format ipv6 address as string
                addr = parts.join(":");
              });

            // unsupported address type
          } else {
            return endConnect(
              RFC_1928_REPLIES.ADDRESS_TYPE_NOT_SUPPORTED,
              buffer,
            );
          }

          args.dst = { addr, port: 0 };
        })
        .word16bu("dst.port")
        .tap(async (args) => {
          if (args.cmd === RFC_1928_COMMANDS.CONNECT) {
            // perform connection
            if (options.filter) {
              const filtered = await options.filter(
                args.dst.port,
                args.dst.addr,
                socket,
              );
              // respond with failure
              if (!filtered)
                return endConnect(
                  RFC_1928_REPLIES.CONNECTION_NOT_ALLOWED,
                  buffer,
                );
            }

            try {
              const destination = await options.connect(
                args.dst.port,
                args.dst.addr,
                socket,
              );

              // we can modify the responseBuffer to inform the client of a new destination IP address and port
              // but we can also just copy the request to confirm the original IP and port
              // TODO: add/update a hook to allow changing the IP and port

              // prepare a success response
              const responseBuffer = Buffer.alloc(buffer.length);
              buffer.copy(responseBuffer);
              responseBuffer[1] = RFC_1928_REPLIES.SUCCEEDED;

              // write acknowledgement to client...
              socket.write(responseBuffer, () => {
                // listen for data bi-directionally
                destination.pipe(socket);
                socket.pipe(destination);
              });
            } catch (err) {
              if (isErrCode(err)) {
                if (err.code === "EADDRNOTAVAIL")
                  endConnect(RFC_1928_REPLIES.HOST_UNREACHABLE, buffer);
                else if (err.code === "ECONNREFUSED")
                  endConnect(RFC_1928_REPLIES.CONNECTION_REFUSED, buffer);
                else if (err.code === "ETIMEDOUT")
                  endConnect(RFC_1928_REPLIES.TTL_EXPIRED, buffer);
                else endConnect(RFC_1928_REPLIES.NETWORK_UNREACHABLE, buffer);
              } else {
                endConnect(RFC_1928_REPLIES.NETWORK_UNREACHABLE, buffer);
                throw err;
              }
            }
          } else {
            // bind and udp associate commands
            return endConnect(RFC_1928_REPLIES.SUCCEEDED, buffer);
          }
        });
    };

    const end = (response: Buffer) => {
      // respond then end the connection
      try {
        socket.end(response);
      } catch (err) {
        // debugOutput("Failure half-closing the client. Destroying stream...");
        socket.destroy();
      }
    };

    /**
     *
     * @param response - reply field
     * @returns RFC 1929 authentication reply
     */
    const authenticateReply = (response: number) => {
      const responseBuffer = Buffer.allocUnsafe(2);
      responseBuffer[0] = RFC_1929_VERSION;
      responseBuffer[1] = response;
      return responseBuffer;
    };

    /**
     * +----+-----+-------+------+----------+----------+
     * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     * +----+-----+-------+------+----------+----------+
     * | 1  |  1  | X'00' |  1   | Variable |    2     |
     * +----+-----+-------+------+----------+----------+
     *
     * @param response - reply field
     * @param responseBuffer - a connect buffer to recycle
     * @returns
     **/
    const endConnect = (response: number, responseBuffer: Buffer) => {
      if (responseBuffer[0] !== RFC_1928_VERSION)
        throw new TypeError("Incorrect function");

      responseBuffer[1] = response;

      // respond then end the connection
      try {
        socket.end(responseBuffer);
      } catch (err) {
        // debugOutput("Failure half-closing the client. Destroying stream...");
        socket.destroy();
      }
    };

    const endHandshake = (response: number) => {
      // either use the raw buffer (if available) or create a new one
      const responseBuffer = Buffer.allocUnsafe(2);
      responseBuffer[0] = RFC_1928_VERSION;
      responseBuffer[1] = response;

      // respond then end the connection
      try {
        socket.end(responseBuffer);
      } catch (err) {
        // debugOutput("Failure half-closing the client. Destroying stream...");
        socket.destroy();
      }
    };

    /**
     * +----+----------+----------+
     * |VER | NMETHODS | METHODS  |
     * +----+----------+----------+
     * | 1  |    1     | 1 to 255 |
     * +----+----------+----------+
     **/
    const handshake = (buffer: Buffer) => {
      stream<{
        ver: number;
        nmethods: number;
        methods: Buffer;
      }>(buffer)
        .word8("ver")
        .word8("nmethods")
        .buffer("methods", "nmethods")
        .tap((args) => {
          // verify version is appropriate
          if (args.ver !== RFC_1928_VERSION) {
            return endHandshake(RFC_1928_REPLIES.GENERAL_FAILURE);
          }

          // convert methods buffer to an array
          const acceptedMethods = [...args.methods];

          const basicAuth = typeof options.authenticate === "function";
          let next = connect;
          const noAuth =
            !basicAuth &&
            typeof acceptedMethods.includes(
              RFC_1928_METHODS.NO_AUTHENTICATION_REQUIRED,
            );

          const responseBuffer = Buffer.allocUnsafe(2);
          responseBuffer[0] = RFC_1928_VERSION;

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
            return endHandshake(RFC_1928_METHODS.NO_ACCEPTABLE_METHODS);
          }

          // respond then listen for cmd and dst info
          socket.write(responseBuffer, () => {
            // now listen for more details
            socket.once("data", next);
          });
        });
    };

    // capture the client handshake
    socket.once("data", handshake);

    // capture socket closure
    socket.once("end", () => {
      // remove the session from currently the active sessions list
      activeSessions.splice(activeSessions.indexOf(socket), 1);
    });
  });
}

export function createProxyServer(
  partialOptions: Partial<ProxyServerOptions> = {},
): Server {
  // stub connect
  if (!partialOptions.connect)
    partialOptions.connect = async (port, host) => {
      const socket = connect(port, host);
      // let the server catch any errors
      await waitForConnect(socket);
      return socket;
    };

  const server = createServer();

  addProxyListeners(server, <ProxyServerOptions>partialOptions);

  return server;
}
