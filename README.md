Node Proxy
================

### An HTTP(s) and SOCKS proxy `http.Agent` implementation for HTTPS

[![Build Status](https://github.com/01101sam/node-proxy-agent/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/01101sam/node-proxy-agent/actions/workflows/test.yml)

This module provides an `http.Agent` implementation that connects to a specified
HTTP, HTTPS and SOCKS proxy server, and can be used with the built-in `https` module.

Specifically, this `Agent` implementation connects to an intermediary "proxy"
server and issues the [CONNECT HTTP method][CONNECT], which tells the proxy to
open a direct TCP connection to the destination server.

Since this agent implements the CONNECT HTTP method, it also works with other
protocols that use this method when connecting over proxies (i.e. WebSockets).

It can also be used in conjunction with the `ws` module to establish a WebSocket
connection over a SOCKS proxy.

See the "Examples" section below for more.

Installation
------------

Install with `npm`:

``` bash
npm i @sam01101/node-proxy-agent
```

Examples
--------

### HttpsProxyAgent

#### `https` module example (TypeScript)

``` js
import fetch from "node-fetch";
import {HttpsProxyAgent} from '@sam01101/node-proxy-agent';


(async () => {
	// HTTP/HTTPS proxy to connect to
	const proxy = process.env.http_proxy || 'http://168.63.76.32:3128';
	console.log('using proxy server %j', proxy);

	// HTTPS endpoint for the proxy to connect to
	const endpoint = process.argv[2] || 'https://graph.facebook.com/tootallnate';
	console.log('attempting to GET %j', endpoint);

	const response = await fetch(endpoint, {
		// create an instance of the `HttpsProxyAgent` class with the proxy server information
		agent: new HttpsProxyAgent(proxy)
	});
	console.log(`HTTP Status: ${response.status} OK: ${response.ok}`);
})();
```

#### `ws` WebSocket connection example

``` js
var url = require('url');
var WebSocket = require('ws');
var HttpsProxyAgent = require('@sam01101/node-proxy-agent');

// HTTP/HTTPS proxy to connect to
var proxy = process.env.http_proxy || 'http://168.63.76.32:3128';
console.log('using proxy server %j', proxy);

// WebSocket endpoint for the proxy to connect to
var endpoint = process.argv[2] || 'ws://echo.websocket.org';
var parsed = url.parse(endpoint);
console.log('attempting to connect to WebSocket %j', endpoint);

// create an instance of the `HttpsProxyAgent` class with the proxy server information
var options = url.parse(proxy);

var agent = new HttpsProxyAgent(options);

// finally, initiate the WebSocket connection
var socket = new WebSocket(endpoint, { agent: agent });

socket.on('open', function () {
  console.log('"open" event!');
  socket.send('hello world');
});

socket.on('message', function (data, flags) {
  console.log('"message" event! %j %j', data, flags);
  socket.close();
});
```

### SocksProxyAgent

#### TypeScript example

```ts
import https from 'https';
import {SocksProxyAgent} from '@sam01101/node-proxy-agent';

const info = {
	hostname: 'br41.nordvpn.com',
	userId: 'your-name@gmail.com',
	password: 'abcdef12345124'
};
const agent = new SocksProxyAgent(info);
https.get('https://ipinfo.io', {agent}, (res) => {
	console.log(res.headers);
	res.pipe(process.stdout);
});
```

#### `http` module example

```js
var url = require('url');
var http = require('http');
var { SocksProxyAgent } = require('@sam01101/node-proxy-agent');
// SOCKS proxy to connect to
var proxy = process.env.socks_proxy || 'socks://127.0.0.1:1080';
console.log('using proxy server %j', proxy);
// HTTP endpoint for the proxy to connect to
var endpoint = process.argv[2] || 'http://nodejs.org/api/';
console.log('attempting to GET %j', endpoint);
var opts = url.parse(endpoint);
// create an instance of the `SocksProxyAgent` class with the proxy server information
var agent = new SocksProxyAgent(proxy);
opts.agent = agent;
http.get(opts, function (res) {
	console.log('"response" event!', res.headers);
	res.pipe(process.stdout);
});
```

#### `https` module example

```js
var url = require('url');
var https = require('https');
var { SocksProxyAgent } = require('@sam01101/node-proxy-agent');
// SOCKS proxy to connect to
var proxy = process.env.socks_proxy || 'socks://127.0.0.1:1080';
console.log('using proxy server %j', proxy);
// HTTP endpoint for the proxy to connect to
var endpoint = process.argv[2] || 'https://encrypted.google.com/';
console.log('attempting to GET %j', endpoint);
var opts = url.parse(endpoint);
// create an instance of the `SocksProxyAgent` class with the proxy server information
var agent = new SocksProxyAgent(proxy);
opts.agent = agent;
https.get(opts, function (res) {
	console.log('"response" event!', res.headers);
	res.pipe(process.stdout);
});
```

#### `ws` WebSocket connection example

``` js
var WebSocket = require('ws');
var { SocksProxyAgent } = require('@sam01101/node-proxy-agent');
// SOCKS proxy to connect to
var proxy = process.env.socks_proxy || 'socks://127.0.0.1:1080';
console.log('using proxy server %j', proxy);
// WebSocket endpoint for the proxy to connect to
var endpoint = process.argv[2] || 'ws://echo.websocket.org';
console.log('attempting to connect to WebSocket %j', endpoint);
// create an instance of the `SocksProxyAgent` class with the proxy server information
var agent = new SocksProxyAgent(proxy);
// initiate the WebSocket connection
var socket = new WebSocket(endpoint, { agent: agent });
socket.on('open', function () {
	console.log('"open" event!');
	socket.send('hello world');
});
socket.on('message', function (data, flags) {
	console.log('"message" event! %j %j', data, flags);
	socket.close();
});
```

API
---

### new HttpsProxyAgent(Object options)

The `HttpsProxyAgent` class implements an `http.Agent` subclass that connects
to the specified "HTTP(s) proxy server" in order to proxy HTTPS and/or WebSocket
requests. This is achieved by using the [HTTP `CONNECT` method][CONNECT].

The `options` argument may either be a string URI of the proxy server to use, or an
"options" object with more specific properties:

* `hostname` - String - Proxy host to connect to. Required.
* `port` - Number - Proxy port to connect to. Required.
* `protocol` - String - If `https:`, then use TLS to connect to the proxy.
* `headers` - Object - Additional HTTP headers to be sent on the HTTP CONNECT method.
* `timeout` - Number - Timeout in milliseconds for the CONNECT method.
* `tls` - `tls.SecureContextOptions` - TLS configuration options.
* `auth` - String - Basic Proxy Authentication for the proxy.
* You can use `username` and `password` instead of `auth`, it will be converted to `auth`.
* Any other options given are passed to the `net.connect()`/`tls.connect()` functions.

### new SocksProxyAgent(Object options)

The `SocksProxyAgent` class implements an `http.Agent` subclass that connects
to the specified "SOCKS proxy server" in order to proxy HTTPS and/or WebSocket
requests.

The `options` argument may either be a string URI of the proxy server to use, or an
"options" object with more specific properties:

* `hostname` - String - Proxy host to connect to. Required.
* `port` - Number - Proxy port to connect to. Required.
* `protocol` - String - Same as `HttpsProxyAgent`.
* `type` - Number - SOCKS version to use. Defaults to 5.
* `tls` - `tls.ConnectionOptions` - TLS options to use for the SOCKS connection.
* `timeout` - Number - Timeout in milliseconds for the CONNECT method.
* `username` - String - Username for the SOCKS proxy.
* `password` - String - Password for the SOCKS proxy.
* You can use `auth` instead of `username` and `password`, it will auto set the `username` and `password` properties.
* Any other options given are passed to the `net.connect()`/`tls.connect()` functions.

[CONNECT]: http://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_Tunneling
