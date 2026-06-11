// Copyright 2012 Timothy J Fontaine <tjfontaine@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

'use strict';

var crypto = require('crypto'),
    net = require('net'),
    util = require('util'),
    EventEmitter = require('events').EventEmitter,
    Packet = require('./packet'),
    consts = require('native-node-dns-packet').consts,
    UDPSocket = require('./utils').UDPSocket,
    TCPSocket = require('./utils').TCPSocket;

var debug = function () {}

if (process.env.NODE_DEBUG && process.env.NODE_DEBUG.match(/dns-queue/)) {
var debug = function() {
  var args = Array.prototype.slice.call(arguments);
  console.log.apply(this, ['pending', Date.now().toString()].concat(args));
};
}

var SocketQueue = function(socket, server) {
  this._active = {};
  this._active_count = 0;
  this._pending = [];

  debug('created', server);

  this._server = server;

  this._socket = socket;
  this._socket.on('ready', this._onlisten.bind(this));
  this._socket.on('message', this._onmessage.bind(this));
  this._socket.on('close', this._onclose.bind(this));
  this._socket.on('error', this._onerror.bind(this));
  this._socket.bind(server);

  this._refd = true;
};
util.inherits(SocketQueue, EventEmitter);

// Upper bound on queued-but-not-yet-sent requests. Without this the backlog
// can grow without limit if requests arrive faster than they drain, leading
// to unbounded memory growth.
var MAX_PENDING = 1000;

SocketQueue.prototype.send = function(request) {
  debug('added', request.question);

  if (this._pending.length >= MAX_PENDING) {
    debug('pending queue full, rejecting', request.question);
    var err = new Error('getHostByName ' + consts.NOMEM);
    err.errno = err.code = consts.NOMEM;
    request.error(err);
    return;
  }

  this._pending.push(request);
  this._fill();
};

SocketQueue.prototype.remove = function(request) {
  var req = this._active[request.id];
  var idx = this._pending.indexOf(request);

  if (req) {
    delete this._active[request.id];
    this._active_count -= 1;
    this._fill();
  }

  if (idx > -1)
    this._pending.splice(idx, 1);

  this._unref();
};

SocketQueue.prototype.close = function() {
  debug('closing', this._server);
  this._clearTimer();
  if (this._socket) {
    this._socket.close();
    this._socket = undefined;
  }
  this.emit('close');
};

SocketQueue.prototype._fill = function() {
  debug('pre fill, active:', this._active_count, 'pending:',
        this._pending.length);

  while (this._listening && this._pending.length &&
         this._active_count < 100) {
    this._dequeue();
  }

  debug('post fill, active:', this._active_count, 'pending:',
        this._pending.length);
};

// DNS transaction IDs must be unpredictable to resist off-path response
// spoofing, so draw them from a CSPRNG over the full 16-bit range.
var random_integer = function() {
  return crypto.randomInt(0, 65536);
};

SocketQueue.prototype._dequeue = function() {
  var req = this._pending.pop();
  var id, packet, dnssocket, k;

  if (req) {
    id = random_integer();

    while (this._active[id])
      id = random_integer();

    debug('sending', req.question, id);

    req.id = id;
    this._active[id] = req;
    this._active_count += 1;

    try {
      packet = new Packet(this._socket.remote(req.server));
      packet.header.id = id;
      packet.header.rd = 1;
      if (req.header) {
        for (k in req.header) {
          if (k in packet.header) {
            packet.header[k] = req.header[k];
          }
        }
      }

      if (req.try_edns) {
        packet.edns_version = 0;
        //TODO when we support dnssec
        //packet.do = 1
      }

      packet.question.push(req.question);
      packet.additional.push.apply(packet.additional, req.additional);
      packet.send();

      this._ref();
    } catch (e) {
      req.error(e);
    }
  }
};

// Guard against off-path spoofing: a response is only accepted if it came
// from the server we queried (for the shared UDP sockets) and its question
// section echoes the question we asked. Matching on the transaction ID alone
// is not sufficient.
SocketQueue.prototype._matches = function(req, packet, remote) {
  // For the shared udp4/udp6 sockets, any host could send to the source
  // port; ensure the datagram originated from the server we queried. TCP
  // sockets are connection-oriented and carry no rinfo, so this is skipped.
  if (remote && remote.address && req.server && req.server.address &&
      remote.address !== req.server.address) {
    return false;
  }

  var q = req.question;
  var rq = packet.question && packet.question[0];

  if (!q || !rq)
    return false;
  if (rq.type !== q.type)
    return false;
  if (q.class != null && rq.class != null && rq.class !== q.class)
    return false;
  if (String(rq.name).toLowerCase() !== String(q.name).toLowerCase())
    return false;

  return true;
};

SocketQueue.prototype._onmessage = function(msg, remote) {
  var req, packet;

  debug('got a message', this._server);

  try {
    packet = Packet.parse(msg, remote);
    req = this._active[packet.header.id];
    debug('associated message', packet.header.id);
  } catch (e) {
    debug('error parsing packet', e);
  }

  if (req && this._matches(req, packet, remote)) {
    delete this._active[packet.header.id];
    this._active_count -= 1;
    req.handle(null, packet);
    this._fill();
  }

  this._unref();
};

SocketQueue.prototype._clearTimer = function() {
  if (this._timer) {
    clearTimeout(this._timer);
    this._timer = null;
  }
};

SocketQueue.prototype._unref = function() {
  var self = this;
  this._refd = false;

  if (this._active_count <= 0) {
    if (this._socket.unref) {
      debug('unrefd socket');
      // Native unref supersedes the fallback idle-close timer; clear any
      // that a prior unref (before the socket was ready) may have scheduled.
      this._clearTimer();
      this._socket.unref();
    } else if (!this._timer) {
      this._timer = setTimeout(function() {
        self.close();
      }, 300);
    }
  }
};

SocketQueue.prototype._ref = function() {
  this._refd = true;
  // Becoming active again always cancels a pending idle-close, regardless of
  // whether the socket also supports native ref/unref.
  this._clearTimer();
  if (this._socket.ref) {
    debug('refd socket');
    this._socket.ref();
  }
};

SocketQueue.prototype._onlisten = function() {
  this._unref();
  this._listening = true;
  this._fill();
};

SocketQueue.prototype._onerror = function(err){
  this._onclose(err);
  return;
}

SocketQueue.prototype._onclose = function(error) {
  var req, err, self = this;

  debug('socket closed', this);

  this._listening = false;

  if(!error){
    err = new Error('getHostByName ' + consts.TIMEOUT);
    err.errno = consts.TIMEOUT;
  }else{
    err = error;
    err.errno = error.code;
  }
  while (this._pending.length) {
    req = this._pending.pop();
    req.error(err);
  }

  Object.keys(this._active).forEach(function(key) {
    var req = self._active[key];
    req.error(err);
    delete self._active[key];
    self._active_count -= 1;
  });

  this._socket = undefined;

  this.close();
};

var serverHash = function(server) {
  if (server.type === 'tcp')
    return server.address + ':' + server.port;
  else
    return 'udp' + net.isIP(server.address);
};

var _sockets = {};

exports.send = function(request) {
  var hash = serverHash(request.server);
  var socket = _sockets[hash];

  if (!socket) {
    switch (hash) {
      case 'udp4':
      case 'udp6':
        socket = new SocketQueue(new UDPSocket(), hash);
        break;
      default:
        socket = new SocketQueue(new TCPSocket(), request.server);
        break;
    }

    socket.on('close', function() {
      delete _sockets[hash];
    });

    _sockets[hash] = socket;
  }

  socket.send(request);
};

exports.remove = function(request) {
  var hash = serverHash(request.server);
  var socket = _sockets[hash];
  if (socket) {
    socket.remove(request);
  }
};
