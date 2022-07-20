/**
 * Module dependencies.
 */

const fs = require('fs')
const url = require('url')
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

describe('HttpsProxyAgent', function () {
	let server
	let serverPort

	let sslServer
	let sslServerPort

	let proxy
	let proxyPort

	let sslProxy
	let sslProxyPort

	before(function (done) {
		// setup target HTTP server
		server = http.createServer()
		server.listen(function () {
			serverPort = parseInt(server.address().port)
			done()
		})
	})

	before(function (done) {
		// setup HTTP proxy server
		proxy = Proxy()
		proxy.listen(function () {
			proxyPort = parseInt(proxy.address().port)
			done()
		})
	})

	before(function (done) {
		// setup target HTTPS server
		let options = {
			key: fs.readFileSync(`${__dirname}/server.key`),
			cert: fs.readFileSync(`${__dirname}/server.pem`)
		}
		sslServer = https.createServer(options)
		sslServer.listen(function () {
			sslServerPort = parseInt(sslServer.address().port)
			done()
		})
	})

	before(function (done) {
		// setup SSL HTTP proxy server
		let options = {
			key: fs.readFileSync(`${__dirname}/server.key`),
			cert: fs.readFileSync(`${__dirname}/server.pem`)
		}
		sslProxy = Proxy(https.createServer(options))
		sslProxy.listen(function () {
			sslProxyPort = parseInt(sslProxy.address().port)
			done()
		})
	})

	// shut down test HTTP server
	after(function (done) {
		server.once('close', function () {
			done()
		})
		server.close()
	})

	after(function (done) {
		proxy.once('close', function () {
			done()
		})
		proxy.close()
	})

	after(function (done) {
		sslServer.once('close', function () {
			done()
		})
		sslServer.close()
	})

	after(function (done) {
		sslProxy.once('close', function () {
			done()
		})
		sslProxy.close()
	})

	describe('constructor', function () {
		it('should throw an Error if no "proxy" argument is given', function () {
			assert.throws(function () {
				new HttpsProxyAgent()
			})
		})
		it('should accept a "string" proxy argument', function () {
			let agent = new HttpsProxyAgent(`http://localhost:${proxyPort}`)
			assert.strictEqual('localhost', agent.proxy.hostname)
			assert.strictEqual(String(proxyPort), agent.proxy.port)
		})
		it('should accept a `new URL()` result object argument', function () {
			let opts = new URL(`http://localhost:${proxyPort}`)
			let agent = new HttpsProxyAgent(opts)
			assert.strictEqual(opts.host, agent.proxy.host)
			assert.strictEqual(String(proxyPort), agent.proxy.port)
		})
		describe('secureEndpoint', function () {
			it('should default to `false`', function () {
				let agent = new HttpsProxyAgent({ port: proxyPort })
				assert.strictEqual(false, agent.proxy.secureEndpoint)
			})
			it('should be `false` when "http:" protocol is used', function () {
				let agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'http:'
				})
				assert.strictEqual(false, agent.proxy.secureEndpoint)
			})
			it('should be `true` when "https:" protocol is used', function () {
				let agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'https:'
				})
				assert.strictEqual(true, agent.proxy.secureEndpoint)
			})
			it('should be `true` when "https" protocol is used', function () {
				let agent = new HttpsProxyAgent({
					port: proxyPort,
					protocol: 'https'
				})
				assert.strictEqual(true, agent.proxy.secureEndpoint)
			})
		})
	})

	describe('"http" module', function () {
		beforeEach(function () {
			delete proxy.authenticate
		})

		it('should work over an HTTP proxy', function (done) {
			server.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxyUri =
				process.env.HTTP_PROXY ||
				process.env.http_proxy ||
				`http://localhost:${proxyPort}`
			let agent = new HttpsProxyAgent(proxyUri)

			let opts = new URL(`http://localhost:${serverPort}`)
			opts.agent = agent

			let req = http.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${serverPort}`, data.host)
					done()
				})
			})
			req.once('error', done)
		})
		it('should work over an HTTP proxy with certs', function (done) {
			sslServer.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxyUri =
				process.env.HTTPS_PROXY ||
				process.env.https_proxy ||
				`http://localhost:${proxyPort}`
			proxyUri = new URL(proxyUri)
			proxyUri.rejectUnauthorized = false
			proxyUri.ca = fs.readFileSync(`${__dirname}/cacert.pem`)

			let agent = new HttpsProxyAgent(proxyUri)

			let opts = new URL(`https://localhost:${sslServerPort}`)
			opts.agent = agent

			https.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			})
		})
		it('should work over an HTTPS proxy', function (done) {
			server.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxyUri =
				process.env.HTTPS_PROXY ||
				process.env.https_proxy ||
				`https://localhost:${sslProxyPort}`
			proxyUri = new URL(proxyUri)
			proxyUri.rejectUnauthorized = false
			let agent = new HttpsProxyAgent(proxyUri)

			let opts = new URL(`http://localhost:${serverPort}`)
			opts.agent = agent

			http.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${serverPort}`, data.host)
					done()
				})
			})
		})
		it('should receive the 407 authorization code on the `http.ClientResponse`', function (done) {
			// set a proxy authentication function for this test
			proxy.authenticate = function (req, fn) {
				// reject all requests
				fn(null, false)
			}

			let proxyUri =
				process.env.HTTP_PROXY ||
				process.env.http_proxy ||
				`http://localhost:${proxyPort}`
			let agent = new HttpsProxyAgent(proxyUri)

			let opts = new URL(`http://localhost:${serverPort}`)
			opts.agent = agent

			let req = http.get(opts, function (res) {
				assert.strictEqual(407, res.statusCode)
				assert('proxy-authenticate' in res.headers)
				done()
			})
			req.once('error', done)
		})
		it('should not error if the proxy responds with 407 and the request is aborted', function (done) {
			proxy.authenticate = function (req, fn) {
				fn(null, false)
			}

			const proxyUri =
				process.env.HTTP_PROXY ||
				process.env.http_proxy ||
				`http://localhost:${proxyPort}`

			const req = http.get(
				{
					agent: new HttpsProxyAgent(proxyUri)
				},
				function (res) {
					assert.strictEqual(407, res.statusCode)
					req.abort()
				}
			)

			req.on('abort', done)
		})
		it('should emit an "end" event on the `http.IncomingMessage` if the proxy responds with non-200 status code', function (done) {
			proxy.authenticate = function (req, fn) {
				fn(null, false)
			}

			const proxyUri =
				process.env.HTTP_PROXY ||
				process.env.http_proxy ||
				`http://localhost:${proxyPort}`

			const req = http.get(
				{
					agent: new HttpsProxyAgent(proxyUri)
				},
				function (res) {
					assert.strictEqual(407, res.statusCode)

					res.resume()
					res.on('end', done)
				}
			)
		})
		it('should emit an "error" event on the `http.ClientRequest` if the proxy does not exist', function (done) {
			// port 4 is a reserved, but "unassigned" port
			let proxyUri = 'http://localhost:4'
			let agent = new HttpsProxyAgent(proxyUri)

			let opts = new URL('http://nodejs.org')
			opts.agent = agent

			let req = http.get(opts)
			req.once('error', function (err) {
				assert.strictEqual('ECONNREFUSED', err.code)
				req.abort()
				done()
			})
		})

		it('should allow custom proxy "headers"', function (done) {
			server.once('connect', function (req, socket, head) {
				assert.strictEqual('CONNECT', req.method)
				assert.strictEqual('bar', req.headers.foo)
				socket.destroy()
				done()
			})

			let uri = `http://localhost:${serverPort}`
			let agent = new HttpsProxyAgent(new URL(uri), {
				headers: {
					Foo: 'bar'
				}
			})

			// `host` and `port` don't really matter since the proxy will reject anyway
			let opts = {
				host: 'localhost',
				port: 80,
				agent: agent
			}

			http.get(opts)
		})
	})

	describe('"https" module', function () {
		it('should work over an HTTP proxy', function (done) {
			sslServer.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxy =
				process.env.HTTP_PROXY ||
				process.env.http_proxy ||
				`http://localhost:${proxyPort}`
			let agent = new HttpsProxyAgent(proxy, {
				ca: fs.readFileSync(`${__dirname}/cacert.pem`)
			})

			let opts = new URL(`https://localhost:${sslServerPort}`)
			opts.rejectUnauthorized = false
			opts.agent = agent

			https.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			})
		})

		it('should work over an HTTPS proxy', function (done) {
			sslServer.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxy =
				process.env.HTTPS_PROXY ||
				process.env.https_proxy ||
				`https://localhost:${sslProxyPort}`
			proxy = new URL(proxy)
			proxy.rejectUnauthorized = false
			let agent = new HttpsProxyAgent(proxy)

			let opts = new URL(`https://localhost:${sslServerPort}`)
			opts.agent = agent
			opts.rejectUnauthorized = false

			https.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual(`localhost:${sslServerPort}`, data.host)
					done()
				})
			})
		})

		it('should not send a port number for the default port', function (done) {
			sslServer.once('request', function (req, res) {
				res.end(JSON.stringify(req.headers))
			})

			let proxy =
				process.env.HTTPS_PROXY ||
				process.env.https_proxy ||
				`https://localhost:${sslProxyPort}`
			proxy = new URL(proxy)
			proxy.rejectUnauthorized = false
			let agent = new HttpsProxyAgent(proxy)
			agent.defaultPort = sslServerPort

			let opts = new URL(`https://localhost:${sslServerPort}`)
			opts.agent = agent
			opts.rejectUnauthorized = false

			https.get(opts, function (res) {
				let data = ''
				res.setEncoding('utf8')
				res.on('data', function (b) {
					data += b
				})
				res.on('end', function () {
					data = JSON.parse(data)
					assert.strictEqual('localhost', data.host)
					done()
				})
			})
		})
	})
})

describe('SocksProxyAgent', function () {
	let httpServer
	let httpPort

	let httpsServer
	let httpsPort

	let socksServer
	let socksPort

	before(function (done) {
		// setup SOCKS proxy server
		socksServer = socks.createServer(function (info, accept, deny) {
			accept()
		})
		socksServer.listen(0, '127.0.0.1', function () {
			socksPort = parseInt(socksServer.address().port)
			done()
		})
		socksServer.useAuth(socks.auth.None())
	})

	before(function (done) {
		// setup target HTTP server
		httpServer = http.createServer()
		httpServer.listen(function () {
			httpPort = parseInt(httpServer.address().port)
			done()
		})
	})

	before(function (done) {
		// setup target SSL HTTPS server
		const options = {
			key: fs.readFileSync(path.resolve(__dirname, 'server.key')),
			cert: fs.readFileSync(path.resolve(__dirname, 'server.pem'))
		}
		httpsServer = https.createServer(options)
		httpsServer.listen(function () {
			httpsPort = parseInt(httpsServer.address().port)
			done()
		})
	})

	after(function (done) {
		socksServer.once('close', function () {
			done()
		})
		socksServer.close()
	})

	after(function (done) {
		httpServer.once('close', function () {
			done()
		})
		httpServer.close()
	})

	after(function (done) {
		httpsServer.once('close', function () {
			done()
		})
		httpsServer.close()
	})

	describe('constructor', function () {
		it('should throw an Error if no "proxy" argument is given', function () {
			assert.throws(() => new SocksProxyAgent())
		})
		it('should accept a "string" proxy argument', function () {
			const agent = new SocksProxyAgent(`socks://127.0.0.1:${socksPort}`)
			assert.strictEqual('127.0.0.1', agent.proxy.host)
			assert.strictEqual(socksPort, agent.proxy.port)
		})
		it('should accept a `new URL()` result object argument', function () {
			const opts = new URL(`socks://127.0.0.1:${socksPort}`)
			const agent = new SocksProxyAgent(opts)
			assert.strictEqual('127.0.0.1', agent.proxy.host)
			assert.strictEqual(socksPort, agent.proxy.port)
		})
		it('setup timeout', function (done) {
			httpServer.once('request', function (req, res) {
				assert.strictEqual('/timeout', req.url)
				res.statusCode = 200
				setTimeout(() => res.end('Written after 1000'), 500)
			})

			const agent = new SocksProxyAgent(`socks://127.0.0.1:${socksPort}`, { timeout: 50 })

			const opts = {
				protocol: 'http:',
				host: `127.0.0.1:${httpPort}`,
				port: httpPort,
				hostname: '127.0.0.1',
				path: '/timeout',
				agent,
				headers: { foo: 'bar' }
			}

			const req = http.get(opts, function () {
			})

			req.once('error', err => {
				assert.strictEqual(err.message, 'socket hang up')
				done()
			})
		})
	})

	describe('"http" module', function () {
		it('should work against an HTTP endpoint', function (done) {
			httpServer.once('request', function (req, res) {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end(JSON.stringify(req.headers))
			})

			const agent = new SocksProxyAgent(`socks://127.0.0.1:${socksPort}`)

			const opts = {
				protocol: 'http:',
				host: `127.0.0.1:${httpPort}`,
				port: httpPort,
				hostname: '127.0.0.1',
				path: '/foo',
				agent,
				headers: { foo: 'bar' }
			}
			const req = http.get(opts, function (res) {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', function (err, buf) {
					if (err) return done(err)
					const data = JSON.parse(buf)
					assert.strictEqual('bar', data.foo)
					done()
				})
			})
			req.once('error', done)
		})
	})

	describe('"https" module', function () {
		it('should work against an HTTPS endpoint', function (done) {
			httpsServer.once('request', function (req, res) {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end(JSON.stringify(req.headers))
			})

			const agent = new SocksProxyAgent(`socks://127.0.0.1:${socksPort}`)

			const opts = {
				protocol: 'https:',
				host: `127.0.0.1:${httpsPort}`,
				port: httpsPort,
				hostname: '127.0.0.1',
				path: '/foo',
				agent,
				rejectUnauthorized: false,
				headers: { foo: 'bar' }
			}

			const req = https.get(opts, function (res) {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', function (err, buf) {
					if (err) return done(err)
					const data = JSON.parse(buf)
					assert.strictEqual('bar', data.foo)
					done()
				})
			})
			req.once('error', done)
		})
	})

	describe('Custom lookup option', function () {

		let dnsServer
		let dnsQueries

		before((done) => {
			dnsQueries = []

			// A custom DNS server that always replies with 127.0.0.1:
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

		after(() => {
			dnsServer.close()
		})

		it('should use a requests\'s custom lookup function with socks5', function (done) {
			httpServer.once('request', function (req, res) {
				assert.strictEqual('/foo', req.url)
				res.statusCode = 404
				res.end()
			})

			let agent = new SocksProxyAgent(`socks5://127.0.0.1:${socksPort}`)
			let opts = url.parse(`http://non-existent-domain.test:${httpPort}/foo`)

			opts.agent = agent
			opts.lookup = (hostname, opts, callback) => {
				if (hostname === 'non-existent-domain.test') callback(null, '127.0.0.1')
				else callback(new Error('Bad domain'))
			}

			let req = http.get(opts, function (res) {
				assert.strictEqual(404, res.statusCode)
				getRawBody(res, 'utf8', function (err, buf) {
					if (err) return done(err)
					done()
				})
			})
			req.once('error', done)
		})

		it('should support caching DNS requests', function (done) {
			httpServer.on('request', function (req, res) {
				res.statusCode = 200
				res.end()
			})

			let agent = new SocksProxyAgent(`socks5://127.0.0.1:${socksPort}`)
			let opts = url.parse(`http://test-domain.test:${httpPort}/foo`)
			opts.agent = agent

			const cacheableLookup = new CacheableLookup()
			cacheableLookup.servers = ['127.0.0.1:5333']
			opts.lookup = cacheableLookup.lookup

			// No DNS queries made initially
			assert.deepEqual(dnsQueries, [])

			http.get(opts, function (res) {
				assert.strictEqual(200, res.statusCode)

				// Initial DNS query for first request
				assert.deepEqual(dnsQueries, [
					{ name: 'test-domain.test', type: dns2.Packet.TYPE.A },
					{ name: 'test-domain.test', type: dns2.Packet.TYPE.AAAA }
				])

				http.get(opts, function (res) {
					assert.strictEqual(200, res.statusCode)

					// Still the same. No new DNS queries, so the response was cached
					assert.deepEqual(dnsQueries, [
						{ name: 'test-domain.test', type: dns2.Packet.TYPE.A },
						{ name: 'test-domain.test', type: dns2.Packet.TYPE.AAAA }
					])
					done()
				}).once('error', done)
			}).once('error', done)
		})
	})
})
