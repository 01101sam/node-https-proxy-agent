import * as net from 'net';
import * as tls from 'tls';
import assert from 'assert';
import dns from 'dns';
import {OutgoingHttpHeaders} from 'http';
import {Agent, AgentOptions, ClientRequest, RequestOptions} from 'agent-base';
import {SocksClient, SocksClientOptions, SocksProxy} from 'socks';
import parseProxyResponse from './parse-proxy-response';
import createDebug from 'debug';

const debug = createDebug('node-proxy-agent:agent');


interface BaseSocksProxyAgentOptions {
	hostname?: string;
	port?: string | number;
	protocol?: string;
	type?: number;
	tls?: tls.ConnectionOptions | null;
	timeout?: number;
	// Auth options
	auth?: string | null;
	username?: string | null;
	password?: string | null;
}

interface BaseHttpsProxyAgentOptions {  // extend BaseSocksProxyAgentOptions
	hostname?: string;
	port?: string | number;
	protocol?: string;
	tls?: tls.SecureContextOptions | null;
	headers?: OutgoingHttpHeaders;
	secureEndpoint?: boolean;  // HTTPS / TLS Connection
	timeout?: number;
	// Auth options
	auth?: string | null;
	username?: string | null;
	password?: string | null;
}

export interface HttpsProxyAgentOptions extends AgentOptions, BaseHttpsProxyAgentOptions, Partial<Omit<URL & net.NetConnectOpts & tls.ConnectionOptions, keyof BaseHttpsProxyAgentOptions>> {
}

export interface SocksProxyAgentOptions extends AgentOptions, BaseSocksProxyAgentOptions, Partial<Omit<URL & SocksProxy, keyof BaseSocksProxyAgentOptions>> {
}

function _normalizeProxyOptions(
	input: string | SocksProxyAgentOptions | HttpsProxyAgentOptions
): SocksProxyAgentOptions | HttpsProxyAgentOptions {
	let proxyOptions
	if (typeof input === 'string') proxyOptions = new URL(input)
	else proxyOptions = input
	if (!proxyOptions) throw new TypeError('A proxy server `host` and `port` must be specified!')

	return proxyOptions
}


/**
 * The `HttpsProxyAgent` implements an HTTP Agent subclass that connects to
 * the specified "HTTP(s) proxy server" in order to proxy HTTPS requests.
 *
 * Outgoing HTTP requests are first tunneled through the proxy server using the
 * `CONNECT` HTTP request method to establish a connection to the proxy server,
 * and then the proxy server connects to the destination target and issues the
 * HTTP request from the proxy server.
 *
 * `https:` requests have their socket connection upgraded to TLS once
 * the connection to the proxy server has been established.
 *
 * @api public
 */
class HttpsProxyAgent extends Agent {
	private readonly tlsSecureContext: tls.SecureContext | undefined
	public readonly proxy: HttpsProxyAgentOptions
	private readonly secureEndpoint: boolean
	public timeout: number | null


	constructor(input: string | HttpsProxyAgentOptions, options?: HttpsProxyAgentOptions) {
		// @ts-ignore
		const proxyOptions: HttpsProxyAgentOptions = Object.assign(_normalizeProxyOptions(input), options || {})
		super(proxyOptions)

		this.proxy = HttpsProxyAgent._parseHttpsProxy(proxyOptions)
		// If `true`, then connect to the proxy server over TLS.
		// Defaults to `false`.
		this.secureEndpoint = Boolean(this.proxy.protocol?.startsWith('https'))
		this.tlsSecureContext = proxyOptions.tls ? tls.createSecureContext(proxyOptions.tls) : undefined
		this.timeout = proxyOptions.timeout ?? null
	}

	private static _parseHttpsProxy(opts: HttpsProxyAgentOptions): HttpsProxyAgentOptions {
		const proxy: HttpsProxyAgentOptions = opts

		if (typeof proxy.port === 'string') proxy.port = parseInt(proxy.port, 10)
		// Use default port for proxy servers if not specified.
		else if (!proxy.port && proxy.host) proxy.port = proxy.secureEndpoint ? 443 : 80

		// ALPN is supported by Node.js >= v5.
		// attempt to negotiate http/1.1 for proxy servers that support http/2
		if (proxy.secureEndpoint && !('ALPNProtocols' in proxy))
			proxy.ALPNProtocols = ['http 1.1']

		// If both a `host` and `path` are specified then it's most likely
		// the result of a `url.parse()` call... we need to remove the
		// `path` portion so that `net.connect()` doesn't attempt to open
		// that as a Unix socket file.
		if (proxy.host && proxy.path) {
			delete proxy.path
			delete proxy.pathname
		}

		// Setup Proxy Auth
		if (!proxy.auth && (opts.username || opts.password)) proxy.auth = `${opts.username || ''}:${opts.password || ''}`

		return proxy
	}

	/**
	 * Called when the node-core HTTP client library is creating a
	 * new HTTP request.
	 *
	 * @api protected
	 */
	async callback(
		req: ClientRequest,
		opts: RequestOptions
	): Promise<net.Socket> {
		const {proxy, secureEndpoint} = this

		const host = await new Promise<string>((resolve, reject) => {
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			try {
				dns.lookup(proxy.hostname!, {}, (err, res) => err ? reject(err) : resolve(res))
			} catch (e) {
				reject(e)
			}
		});

		proxy.host = host;

		// Create a socket connection to the proxy server.
		debug(`Creating \`${secureEndpoint ? 'tls' : 'net'}.Socket\`: %o`, proxy)
		const socket: net.Socket = secureEndpoint ? tls.connect(proxy as tls.ConnectionOptions) : net.connect(proxy as net.NetConnectOpts)

		if (this.timeout != null && this.timeout >= 0) {
			socket.setTimeout(this.timeout)
			socket.on('timeout', () => {
				debug('Socket timeout on connect')
				socket.end()
			})
		}

		const headers: OutgoingHttpHeaders = {...proxy.headers}
		const hostname = `${opts.host}:${opts.port}`
		let payload = `CONNECT ${hostname} HTTP/1.1\r\n`

		// Inject the `Proxy-Authorization` header if necessary.
		if (proxy.auth) headers['Proxy-Authorization'] = `Basic ${Buffer.from(proxy.auth).toString('base64')}`

		headers.Host = hostname
		headers.Connection = 'close'

		for (const name of Object.keys(headers)) payload += `${name}: ${headers[name]}\r\n`

		const proxyResponsePromise = parseProxyResponse(socket)

		socket.write(`${payload}\r\n`)

		const {
			statusCode,
			buffered
		} = await proxyResponsePromise

		debug(`Response from proxy server: ${statusCode}`)
		if (statusCode === 200) {
			req.once('socket', (socket: net.Socket | tls.TLSSocket) => socket.resume())

			if (opts.secureEndpoint) {
				// The proxy is connecting to a TLS server, so upgrade
				// this socket connection to a TLS connection.
				debug('Upgrading socket connection to TLS')
				const tlsSocket = tls.connect({
					...omit(opts, 'host', 'hostname', 'path', 'port'),
					socket,
					servername: opts.servername || opts.host,
					secureContext: this.tlsSecureContext
				})
				return new Promise((resolve, reject) => {
					const errCb = (err: Error) => reject(err)
					tlsSocket.once('error', errCb)

					tlsSocket.once('secureConnect', () => {
						resolve(tlsSocket)
						tlsSocket.off('error', errCb)
					})
				})
			}

			return socket
		}

		// Some other status code that's not 200... need to re-play the HTTP
		// header "data" events onto the socket once the HTTP machinery is
		// attached so that the node core `http` can parse and handle the
		// error status code.

		// Close the original socket, and a new "fake" socket is returned
		// instead, so that the proxy doesn't get the HTTP request
		// written to it (which may contain `Authorization` headers or other
		// sensitive data).
		//
		// See: https://hackerone.com/reports/541502
		socket.destroy()

		// Need to wait for the "socket" event to re-play the "data" events.
		req.once('socket', (s: net.Socket) => {
			debug('replaying proxy buffer for failed request')
			assert(s.listenerCount('data') > 0)

			// Replay the "buffered" Buffer onto the fake `socket`, since at
			// this point the HTTP module machinery has been hooked up for
			// the user.
			s.push(buffered)
			s.push(null)
		})

		return new net.Socket({writable: false, readable: true})
	}
}

/**
 * The `SocksProxyAgent` implements an HTTP Agent subclass that connects to
 * the specified "SOCKS proxy server" in order to proxy HTTPS requests.
 *
 * @api public
 */
class SocksProxyAgent extends Agent {
	private readonly tlsConnectionOptions: tls.ConnectionOptions | undefined
	public readonly proxy: SocksProxy
	public timeout: number | null

	constructor(input: string | SocksProxyAgentOptions, options?: SocksProxyAgentOptions) {
		// @ts-ignore
		const proxyOptions: SocksProxyAgentOptions = Object.assign(_normalizeProxyOptions(input), options || {})
		super(proxyOptions)

		this.proxy = SocksProxyAgent._parseSocksProxy(proxyOptions)
		this.tlsConnectionOptions = proxyOptions.tls != null ? proxyOptions.tls : {}
		this.timeout = proxyOptions.timeout ?? null
	}

	private static _parseSocksProxy(opts: SocksProxyAgentOptions): SocksProxy {
		let port
		let type: SocksProxy['type'] = 5

		if (!opts.hostname) throw new TypeError('You didn\'t specify "hostname" in options!')

		if (typeof opts.port === 'string') port = parseInt(opts.port, 10)
		else if (typeof opts.port === 'number') port = opts.port
		/*
			From RFC 1928, Section 3: https://tools.ietf.org/html/rfc1928#section-3
			"The SOCKS service is conventionally located on TCP port 1080"
		 */
		else port = 1080

		if (!opts.type) opts.type = opts.protocol === 'socks5' ? 5 : 4
		if (![4, 5].includes(<number>opts.type)) throw new TypeError(`"type" must be 4 or 5, got: ${String(opts.type)}`)

		const proxy: SocksProxy = {
			host: opts.hostname,
			port,
			type
		}

		// Setup Proxy Auth

		let username
		let password
		if (opts.auth) {
			[username, password] = opts.auth.split(':')
		} else {
			username = opts.username
			password = opts.password
		}
		if (username) {
			Object.defineProperty(proxy, 'userId', {
				value: username,
				enumerable: false
			})
		}
		if (password) {
			Object.defineProperty(proxy, 'password', {
				value: password,
				enumerable: false
			})
		}

		return proxy
	}

	/**
	 * Initiates a SOCKS connection to the specified SOCKS proxy server,
	 * which in turn connects to the specified remote host and port.
	 *
	 * @api protected
	 */
	async callback(
		req: ClientRequest,
		opts: RequestOptions
	): Promise<net.Socket> {
		const {proxy, timeout} = this
		let {host, port, lookup: lookupCallback} = opts

		if (!host) throw new Error('No `host` defined!')

		// Client-side DNS resolution for "4" and "5" socks proxy versions.
		host = await new Promise<string>((resolve, reject) => {
			// Use the request's custom lookup, if one was configured:
			const lookupFn = lookupCallback ?? dns.lookup
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			try {
				lookupFn(host!, {}, (err, res) => err ? reject(err) : resolve(res))
			} catch (e) {
				reject(e)
			}
		})

		const socksOpts: SocksClientOptions = {
			proxy,
			destination: {host, port},
			command: 'connect',
			timeout: timeout ?? undefined
		}

		const cleanup = (tlsSocket?: tls.TLSSocket) => {
			req.destroy()
			socket.destroy()
			if (tlsSocket) tlsSocket.destroy()
		}

		debug('Creating socks proxy connection: %o', socksOpts)
		const {socket} = await SocksClient.createConnection(socksOpts)
		debug('Successfully created socks proxy connection')

		if (timeout !== null) {
			socket.setTimeout(timeout)
			socket.on('timeout', () => cleanup())
		}

		if (opts.secureEndpoint) {
			// The proxy is connecting to a TLS server, so upgrade
			// this socket connection to a TLS connection.
			debug('Upgrading socket connection to TLS')
			const servername = opts.servername ?? opts.host

			const tlsSocket = tls.connect({
				...omit(opts, 'host', 'hostname', 'path', 'port'),
				socket,
				servername,
				...this.tlsConnectionOptions
			})

			tlsSocket.once('error', (error) => {
				debug('socket TLS error', error.message)
				cleanup(tlsSocket)
			})

			return tlsSocket
		}

		return socket
	}
}


function omit<T extends object, K extends [...(keyof T)[]]>(
	obj: T,
	...keys: K
): {
	[K2 in Exclude<keyof T, K[number]>]: T[K2]
} {
	const ret = {} as {
		[K in keyof typeof obj]: typeof obj[K]
	}
	let key: keyof typeof obj
	for (key in obj) if (!keys.includes(key)) ret[key] = obj[key]
	return ret
}

export {
	HttpsProxyAgent,
	SocksProxyAgent
}
