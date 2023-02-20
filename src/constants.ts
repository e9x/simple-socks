export const RFC_1928_ATYP = {
  DOMAINNAME: 0x03,
  IPV4: 0x01,
  IPV6: 0x04,
};

export const LENGTH_RFC_1928_ATYP = 4;

export const RFC_1928_COMMANDS = {
  BIND: 0x02,
  CONNECT: 0x01,
  UDP_ASSOCIATE: 0x03,
};

export const RFC_1928_METHODS = {
  BASIC_AUTHENTICATION: 0x02,
  GSSAPI: 0x01,
  NO_ACCEPTABLE_METHODS: 0xff,
  NO_AUTHENTICATION_REQUIRED: 0x00,
};

export const RFC_1928_REPLIES = {
  ADDRESS_TYPE_NOT_SUPPORTED: 0x08,
  COMMAND_NOT_SUPPORTED: 0x07,
  CONNECTION_NOT_ALLOWED: 0x02,
  CONNECTION_REFUSED: 0x05,
  GENERAL_FAILURE: 0x01,
  HOST_UNREACHABLE: 0x04,
  NETWORK_UNREACHABLE: 0x03,
  SUCCEEDED: 0x00,
  TTL_EXPIRED: 0x06,
};

export const RFC_1928_VERSION = 0x05;

export const RFC_1929_REPLIES = {
  GENERAL_FAILURE: 0xff, // not X'00'
  SUCCEEDED: 0x00,
};

export const RFC_1929_VERSION = 0x01;
