/**
 * Module dependencies.
 */

const fs = require('fs')
const http = require('http')
const https = require('https')
const assert = require('assert')
const path = require('path')
const socks = require('socksv5')
const Proxy = require('proxy')
const dns2 = require('dns2')
const CacheableLookup = require('cacheable-lookup')
const getRawBody = require('raw-body')

const { HttpsProxyAgent, SocksProxyAgent } = require('..')

describe('HttpsProxyAgent', () => {
	let server
	let serverPort

	let sslServer
	let sslServerPort

	let proxy
	let proxyPort

	let sslProxy
	let sslProxyPort

	before(done => {
		// setup target HTTP server
		server = http.createServer()
		server.listen(() => {
			serverPort = parseInt(server.address().port)
			done()
		})
		server.on('error', err => console.error(err) && process.exit(1))
	})

	before(done => {
		// setup HTTP proxy server
		proxy = Proxy()
		proxy.listen(() => {
			proxyPort = parseInt(proxy.address().port)
			done()
		})
	})

	before(done => {
		// setup target HTTPS server
		sslServer = https.createServer({
			key: fs.readFileSync(path.resolve(__dirname, 'server.key')),
			cert: fs.readFileSync(path.resolve(__dirname, 'server.pem'))
		})
		sslServer.listen(() => {
			sslServerPort = parseInt(sslServer.address().port)
			done()
		})
	})

	before(done => {
		// setup SSL HTTP proxy server
		sslProxy = Proxy(https.createServer({
			key: fs.readFileSync(path.resolve(__dirname, 'server.key')),
			cert: fs.readFileSync(path.resolve(__dirname, 'server.pem'))
		}))
		sslProxy.listen(() => {
			sslProxyPort = parseInt(sslProxy.address().port)
			done()
		})
	})

	// shut down test HTTP server
	after(done => {
		server.once('close', done)
		server.close()
	})

	after(done => {
		proxy.once('close', done)
		proxy.close()
	})

	after(done => {
		sslServer.once('close', done)
		sslServer.close()
	})

	after(done => {
		sslProxy.once('close', done)
		sslProxy.close()
	})

	describe('constructor', () => {
		it('should throw an Error if no "proxy" argument is given', () => assert.throws(() => new HttpsProxyAgent()))
		it('should accept a "string" proxy argument', () => {
			const agent = new HttpsProxyAgent(`http://localhost:${proxyPort}`)
			assert.strictEqual('localhost', agent.proxy.hostname)
			assert.strictEqual(proxyPort, agent.proxy.port)
		})
		it('should accept a `new URL()` result object argument', () => {
			const opts = new URL(`http://localhost:${proxyPort}`)
			const agent = new HttpsProxyAgent(opts)
			assert.strictEqual(opts.host, agent.proxy.host)
			assert.strictEqual(String(proxyPort), agent.proxy.port)
		})
		describe('secureEndpoint', () => {
			it('should default to `false`', () => {
				const agent = new HttpsProxyAgent({ port: proxyPort })
				assert.strictEqual(false, agent.secureEndpoint)
			})
			it('should be `false` when "http:" protocol is used', () => {
				const agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'http:'
				})
				assert.strictEqual(false, agent.secureEndpoint)
			})
			it('should be `true` when "https:" protocol is used', () => {
				const agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'https:'
				})
				assert.strictEqual(true, agent.secureEndpoint)
			})
			it('should be `true` when "https" protocol is used', () => {
				const agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'https'
				})
				assert.strictEqual(true, agent.secureEndpoint)
			})
		})
	})

	describe('"http" module', () => {
		beforeEach(() => delete proxy.authenticate)

		it('should work over an HTTP proxy', done => {
			server.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			http.get({
				protocol: 'http:',
				host: `localhost:${serverPort}`,
				port: serverPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http'
				})
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					assert.strictEqual(200, res.statusCode)
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${serverPort}`, data.host)
					done()
				})
			})
				.once('error', done)
		})
		it('should work over an HTTPS proxy', done => {
			server.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			http.get({
				protocol: 'http:',
				host: `localhost:${serverPort}`,
				port: serverPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent(`https://localhost:${sslProxyPort}`,{
					// hostname: 'localhost',
					// port: sslProxyPort,
					// protocol: 'https',
					tls: {
						ca: fs.readFileSync(`${__dirname}/cacert.pem`)
					},
					rejectUnauthorized: false
				})
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${serverPort}`, data.host)
					done()
				})
			})
				.once('error', done)
		})
		it('should work over an HTTP proxy with certs', done => {
			sslServer.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			https.get({
				protocol: 'https:',
				host: `localhost:${sslServerPort}`,
				port: sslServerPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http',
					tls: {  // Actually, this is not necessary, but it's here for the sake of testing
						ca: fs.readFileSync(path.resolve(__dirname, 'cacert.pem'))
					}
				}),
				rejectUnauthorized: false
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			})
				.once('error', done)
		})
		it('should work over an HTTP proxy with proxy authentication', done => {
			const auth = 'username:password'
			// set a proxy authentication function for this test
			proxy.authenticate = (req, fn) => {
				assert.strictEqual(`Basic ${Buffer.from(auth).toString('base64')}`, req.headers['proxy-authorization'])
				fn(null, false)
				done()
			}

			http.get({
				protocol: 'http:',
				host: `localhost:1234`,
				port: 1234,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					protocol: 'http',
					port: proxyPort,
					auth
				})
			}).once('error', done)
		})
		it('should receive the 407 authorization code on the `http.ClientResponse`', done => {
			// set a proxy authentication function for this test
			// reject all requests
			proxy.authenticate = (req, fn) => fn(null, false)

			http.get({
				protocol: 'http:',
				host: `localhost:${proxyPort}`,
				port: proxyPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http'
				})
			}, res => {
				assert.strictEqual(407, res.statusCode)
				assert('proxy-authenticate' in res.headers)
				done()
			})
				.once('error', done)
		})
		it('should not error if the proxy responds with 407 and the request is aborted', done => {
			proxy.authenticate = (req, fn) => fn(null, false)

			const req = http.get({
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http'
				})
			}, res => {
				assert.strictEqual(407, res.statusCode)
				req.abort()
			})
				.once('error', done)
				.once('abort', done)
		})
		it('should emit an "end" event on the `http.IncomingMessage` if the proxy responds with non-200 status code', done => {
			proxy.authenticate = (req, fn) => fn(null, false)

			http.get({
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http'
				})
			}, res => {
				assert.strictEqual(407, res.statusCode)

				res.resume()
				res.once('end', done)
			})
				.once('error', done)
		})
		it('should emit an "error" event on the `http.ClientRequest` if the proxy does not exist', done => {
			const req = http.get({
				protocol: 'http:',
				host: `nodejs.org`,
				port: proxyPort,
				hostname: 'nodejs.org',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: 4,  // port 4 is a reserved, but "unassigned" port
					protocol: 'http'
				})
			})
				.once('error', err => {
					assert.strictEqual('ECONNREFUSED', err.code)
					req.destroy()
					done()
				})
		})
		it('should allow custom proxy "headers"', done => {
			server.once('connect', (req, socket, _) => {
				assert.strictEqual('CONNECT', req.method)
				assert.strictEqual('bar', req.headers.foo)
				socket.destroy()
				done()
			})

			http.get({
				protocol: 'http:',
				// `host` and `port` don't really matter since the proxy will reject anyway
				host: 'localhost:80',
				port: 80,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: serverPort,
					protocol: 'http',
					headers: {
						Foo: 'bar'
					}
				})
			})
				.once('error', done)
		})
	})

	describe('"https" module', () => {
		it('should work over an HTTP proxy', done => {
			sslServer.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			https.get({
				protocol: 'https:',
				host: `localhost:${sslServerPort}`,
				port: sslServerPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: proxyPort,
					protocol: 'http',
					rejectUnauthorized: false
				}),
				rejectUnauthorized: false
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			})
				.once('error', done)
		})
		it('should work over an HTTPS proxy', done => {
			sslServer.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			https.get({
				protocol: 'https:',
				host: `localhost:${sslServerPort}`,
				port: sslServerPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					hostname: 'localhost',
					port: sslProxyPort,
					protocol: 'https',
					rejectUnauthorized: false
				}),
				rejectUnauthorized: false
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			}).once('error', done)
		})
		it('should not send a port number for the default port', done => {
			sslServer.once('request', (req, res) => res.end(JSON.stringify(req.headers)))

			https.get({
				protocol: 'https:',
				host: `localhost:${sslServerPort}`,
				port: sslServerPort,
				hostname: 'localhost',
				path: '/',
				agent: new HttpsProxyAgent({
					defaultPort: sslServerPort,
					hostname: 'localhost',
					port: sslProxyPort,
					protocol: 'https',
					rejectUnauthorized: false
				}),
				rejectUnauthorized: false
			}, res => {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', b => data += b)
				res.once('end', () => {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			}).once('error', done)
		})
	})
})

describe('SocksProxyAgent', () => {
	let httpServer
	let httpPort

	let httpsServer
	let httpsPort

	let socksServer
	let socksPort

	before(done => {
		// setup SOCKS proxy server
		socksServer = socks.createServer((info, accept, _) => accept())
		socksServer.listen(0, 'localhost', () => {
			socksPort = parseInt(socksServer.address().port)
			done()
		})
		socksServer.useAuth(socks.auth.None())
	})

	before(done => {
		// setup target HTTP server
		httpServer = http.createServer()
		httpServer.listen(() => {
			httpPort = parseInt(httpServer.address().port)
			done()
		})
	})

	before(done => {
		// setup target SSL HTTPS server
		httpsServer = https.createServer({
			key: fs.readFileSync(path.resolve(__dirname, 'server.key')),
			cert: fs.readFileSync(path.resolve(__dirname, 'server.pem'))
		})
		httpsServer.listen(() => {
			httpsPort = parseInt(httpsServer.address().port)
			done()
		})
	})

	after(done => {
		socksServer.once('close', done)
		socksServer.close()
	})

	after(done => {
		httpServer.once('close', done)
		httpServer.close()
	})

	after(done => {
		httpsServer.once('close', done)
		httpsServer.close()
	})

	describe('constructor', () => {
		it('should throw an Error if no "proxy" argument is given', () => assert.throws(() => new SocksProxyAgent()))
		it('should accept a "string" proxy argument', () => {
			const agent = new SocksProxyAgent(`socks://localhost:${socksPort}`)
			assert.strictEqual('localhost', agent.proxy.host)
			assert.strictEqual(socksPort, agent.proxy.port)
		})
		it('should accept a `new URL()` result object argument', () => {
			const agent = new SocksProxyAgent(new URL(`socks://localhost:${socksPort}`))
			assert.strictEqual('localhost', agent.proxy.host)
			assert.strictEqual(socksPort, agent.proxy.port)
		})
		it('setup timeout', done => {
			httpServer.once('request', (req, res) => {
				assert.strictEqual('/timeout', req.url)
				res.statusCode = 200
				setTimeout(() => res.end('Written after 1000'), 500)
			})

			http.get({
				protocol: 'http:',
				host: `localhost:${httpPort}`,
				port: httpPort,
				hostname: 'localhost',
				path: '/timeout',
				agent: new SocksProxyAgent(`socks://localhost:${socksPort}`, { timeout: 50 }),
				headers: { foo: 'bar' }
			}).once('error', err => {
				assert.strictEqual(err.message, 'socket hang up')
				done()
			})
		})
	})

	describe('"http" module', () => {
		it('should work against an HTTP endpoint', done => {
			httpServer.once('request', (req, res) => {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end(JSON.stringify(req.headers))
			})

			http.get({
				protocol: 'http:',
				host: `localhost:${httpPort}`,
				port: httpPort,
				hostname: 'localhost',
				path: '/foo',
				agent: new SocksProxyAgent(`socks://localhost:${socksPort}`),
				headers: { foo: 'bar' }
			}, res => {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', (err, buf) => {
					if (err) return done(err)
					const data = JSON.parse(buf)
					assert.strictEqual('bar', data.foo)
					done()
				})
			}).once('error', done)
		})
		it('should work against an HTTP endpoint with proxy authentication', done => {
			httpServer.once('request', (req, res) => {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end(JSON.stringify(req.headers))
			})

			socksServer._auths.unshift(socks.auth.UserPassword(function (user, password, cb) {
				assert.strictEqual('username', user)
				assert.strictEqual('password', password)
				socksServer._auths.shift()
				cb(true)
				done()
			}))

			http.get({
				protocol: 'http:',
				host: `localhost:${httpPort}`,
				port: httpPort,
				hostname: 'localhost',
				path: '/foo',
				agent: new SocksProxyAgent({
					hostname: 'localhost',
					port: socksPort,
					protocol: 'socks5',
					type: 5,
					username: 'username',
					password: 'password'
				})
			}).once('error', done)
		})
	})

	describe('"https" module', () => {
		it('should work against an HTTPS endpoint', done => {
			httpsServer.once('request', (req, res) => {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end(JSON.stringify(req.headers))
			})

			https.get({
				protocol: 'https:',
				host: `localhost:${httpsPort}`,
				port: httpsPort,
				hostname: 'localhost',
				path: '/foo',
				agent: new SocksProxyAgent(`socks://localhost:${socksPort}`),
				rejectUnauthorized: false,
				headers: { foo: 'bar' }
			}, res => {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', (err, buf) => {
					if (err) return done(err)
					const data = JSON.parse(buf)
					assert.strictEqual('bar', data.foo)
					done()
				})
			}).once('error', done)
		})
	})

	describe('Custom lookup option', () => {

		let dnsServer
		let dnsQueries

		before(done => {
			dnsQueries = []

			// A custom DNS server that always replies with localhost:
			dnsServer = dns2.createServer({
				udp: true,
				handle: (request, send) => {
					const response = dns2.Packet.createResponseFromRequest(request)
					const [question] = request.questions
					const { name } = question

					dnsQueries.push({ type: question.type, name: question.name })

					response.answers.push({
						name,
						type: dns2.Packet.TYPE.A,
						class: dns2.Packet.CLASS.IN,
						ttl: 300,
						address: '127.0.0.1'
					})
					send(response)
				}
			})
			dnsServer.listen({ udp: 5333 })
			dnsServer.on('listening', () => done())
		})

		after(() => dnsServer.close())

		it('should use a request\'s custom lookup function with socks5', done => {
			httpServer.once('request', (req, res) => {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end()
			})

			http.get({
				protocol: 'http:',
				host: `non-existent-domain.test:${httpPort}`,
				port: httpPort,
				hostname: 'non-existent-domain.test',
				path: '/foo',
				agent: new SocksProxyAgent(`socks5://localhost:${socksPort}`),
				lookup: (hostname, opts, callback) => {
					if (hostname === 'non-existent-domain.test') callback(null, 'localhost')
					else callback(new Error('Bad domain'))
				}
			}, res => {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', (err, _) => {
					if (err) return done(err)
					done()
				})
			})
				.once('error', done)
		})
		it('should support caching DNS requests', done => {
			httpServer.on('request', (req, res) => {
				res.statusCode = 200
				res.end()
			})

			const cacheableLookup = new CacheableLookup()
			cacheableLookup.servers = ['127.0.0.1:5333']

			// No DNS queries made initially
			assert.deepStrictEqual(dnsQueries, [])

			const opts = {
				protocol: 'http:',
				host: `test-domain.test:${httpPort}`,
				port: httpPort,
				hostname: 'test-domain.test',
				path: '/foo',
				agent: new SocksProxyAgent(`socks5://127.0.0.1:${socksPort}`),
				lookup: cacheableLookup.lookup
			}

			http.get(opts, res => {
				assert.strictEqual(200, res.statusCode)

				// Initial DNS query for first request
				assert.deepStrictEqual(dnsQueries, [
					{ name: 'test-domain.test', type: dns2.Packet.TYPE.A },
					{ name: 'test-domain.test', type: dns2.Packet.TYPE.AAAA }
				])

				http.get(opts, res => {
					assert.strictEqual(200, res.statusCode)

					// Still the same. No new DNS queries, so the response was cached
					assert.deepStrictEqual(dnsQueries, [
						{ name: 'test-domain.test', type: dns2.Packet.TYPE.A },
						{ name: 'test-domain.test', type: dns2.Packet.TYPE.AAAA }
					])
					done()
				}).once('error', done)
			}).once('error', done)
		})
	})
})
