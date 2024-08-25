# Proxy

A fast, lightweight proxy written in Golang that supports authentication and custom listening ports.

## Features

- Proxy for HTTP and HTTPS requests
- Basic authentication
- Customizable configuration via JSON file
- Logging of incoming requests with client IP address
- Management of HTTPS connections via tunneling
- Customizable listening port

## Configuration

The program uses a `config.json` configuration file to define operating parameters. Here's an example of configuration:

```json
{
    "port": "8080",
    "username": "username",
    "password": "password",
    "realm": "Proxy"
}
```

If the `config.json` file does not exist when the program is launched, a file with default values will be created automatically.

## Usage

### Download latest release

1. Visite https://github.com/mecperspicace/proxy/releases and download the file corresponding to your operating system.
2. Run the file and edit `config.json`

### Run from source

1. Make sure Go is installed on your system.
2. Clone this repository with `git clone https://github.com/mecperspicace/proxy.git`.
3. Open folder with `cd proxy`.
4. Run the program with the command: `go run main.go`.
5. The proxy will start listening on the port specified in the configuration.

## Main functions

### `handleTunneling`

This function handles CONNECT requests for HTTPS connections. It establishes a TCP connection with the destination server and creates a tunnel between client and server.

### `handleHTTP`

This function handles standard HTTP requests, transmitting them to the destination server and returning the response to the client.

### `basicAuth`

Implements basic authentication for the proxy. It checks the credentials provided by the client and denies access if authentication fails.

### `loadConfig`

Loads configuration from JSON file.

### `getClientIP`

Determines the client's IP address, taking into consideration any proxy headers.

### `createDefaultConfigIfNotExist`

Creates a default configuration file if none exists.

## HTTPS request management

The proxy handles HTTPS requests using the tunneling method:

1. The client sends a CONNECT request to the proxy.
2. The proxy establishes a TCP connection with the destination server.
3. If the connection is successful, the proxy replies to the client with a 200 OK code.
4. The proxy then uses the `transfer` function to relay data bidirectionally between client and server.

## Customize listening port

The listening port can be customized by modifying the “port” value in the `config.json` file.

## Security

- The program uses `crypto/subtle.ConstantTimeCompare` for ID comparison, offering protection against temporal attacks.
- Authentication is required for all requests.
- HTTPS connections are handled securely via tunneling.

## Warning

This proxy is designed for educational and testing purposes. It is not recommended for production use without a thorough security review and appropriate modifications.

## Contribution

Contributions are welcome! Feel free to open an issue or submit a pull request for any improvement or bug fix.

