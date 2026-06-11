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

var dgram = require('dgram'),
    EventEmitter = require('events').EventEmitter,
    net = require('net'),
    util = require('util');

var UDPSocket = exports.UDPSocket = function(socket, remote) {
  this._socket = socket;
  this._remote = remote;
  this._buff = undefined;
  this.base_size = 512;
  this.bound = false;
  this.unref = undefined;
  this.ref = undefined;
};
util.inherits(UDPSocket, EventEmitter);

UDPSocket.prototype.buffer = function(size) {
  this._buff = Buffer.alloc(size);
  return this._buff;
};

UDPSocket.prototype.send = function(len) {
  this._socket.send(this._buff, 0, len, this._remote.port,
                    this._remote.address);
};

UDPSocket.prototype.bind = function(type) {
  var self = this;

  if (this.bound) {
    this.emit('ready');
  } else {
    this._socket = dgram.createSocket(type);
    this._socket.on('listening', function() {
      self.bound = true;
      if (self._socket.unref) {
        self.unref = function() {
          self._socket.unref();
        }
        self.ref = function() {
          self._socket.ref();
        }
      }
      self.emit('ready');
    });

    this._socket.on('message', this.emit.bind(this, 'message'));

    this._socket.on('close', function() {
      self.bound = false;
      self.emit('close');
    });

    this._socket.bind();
  }
};

UDPSocket.prototype.close = function() {
  this._socket.close();
};

UDPSocket.prototype.remote = function(remote) {
  return new UDPSocket(this._socket, remote);
};

var TCPSocket = exports.TCPSocket = function(socket) {
  UDPSocket.call(this, socket);
  this.base_size = 4096;
  this._rest = undefined;
};
util.inherits(TCPSocket, UDPSocket);

TCPSocket.prototype.buffer = function(size) {
  this._buff = Buffer.alloc(size + 2);
  return this._buff.slice(2);
};

TCPSocket.prototype.send = function(len) {
  this._buff.writeUInt16BE(len, 0);
  this._socket.write(this._buff.slice(0, len + 2));
};

TCPSocket.prototype.bind = function(server) {
  var self = this;

  if (this.bound) {
    this.emit('ready');
  } else {
    this._socket = net.connect(server.port, server.address);

    this._socket.on('connect', function() {
      self.bound = true;
      if (self._socket.unref) {
        self.unref = function() {
          self._socket.unref();
        }
        self.ref = function() {
          self._socket.ref();
        }
      }
      self.emit('ready');
    });

    this._socket.on('error',function(err) {
      self.emit('error', err)
    });

    this._socket.on('timeout', function() {
      self.bound = false;
      self.emit('close');
    });

    this._socket.on('close', function() {
      self.bound = false;
      self.emit('close');
    });

    this.catchMessages();
  }
};

TCPSocket.prototype.catchMessages = function() {
  var self = this;
    this._socket.on('error', function(err) {
      self.bound = false;
      self.emit('close', err);
  });
  this._socket.on('data', function(data) {
    var len, tmp;
    if (!self._rest) {
      self._rest = data;
    } else {
      tmp = Buffer.alloc(self._rest.length + data.length);
      self._rest.copy(tmp, 0);
      data.copy(tmp, self._rest.length);
      self._rest = tmp;
    }
    while (self._rest && self._rest.length > 2) {
      len = self._rest.readUInt16BE(0);
      if (self._rest.length >= len + 2) {
        self.emit('message', self._rest.slice(2, len + 2), self);
        self._rest = self._rest.slice(len + 2);
      } else {
        break;
      }
    }
  });
};

TCPSocket.prototype.close = function() {
  this._socket.end();
};

TCPSocket.prototype.remote = function() {
  return this;
};

// Expand a valid IPv6 string into its 16 constituent bytes. Handles "::"
// zero-compression and embedded IPv4 (e.g. "::ffff:192.0.2.1").
function ipv6ToBytes(ip) {
  // Convert any trailing embedded IPv4 dotted-quad into two hextets.
  if (ip.indexOf('.') !== -1) {
    var lastColon = ip.lastIndexOf(':');
    var v4 = ip.slice(lastColon + 1).split('.');
    var hi = ((parseInt(v4[0], 10) << 8) | parseInt(v4[1], 10)).toString(16);
    var lo = ((parseInt(v4[2], 10) << 8) | parseInt(v4[3], 10)).toString(16);
    ip = ip.slice(0, lastColon + 1) + hi + ':' + lo;
  }

  var halves = ip.split('::');
  var head = halves[0] ? halves[0].split(':') : [];
  var tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  var groups;

  if (halves.length > 1) {
    var missing = 8 - head.length - tail.length;
    var fill = [];
    for (var i = 0; i < missing; i++) {
      fill.push('0');
    }
    groups = head.concat(fill, tail);
  } else {
    groups = head;
  }

  var bytes = [];
  groups.forEach(function(g) {
    var val = parseInt(g || '0', 16);
    bytes.push((val >> 8) & 0xff);
    bytes.push(val & 0xff);
  });
  return bytes;
}

exports.reverseIP = function(ip) {
  var reverseip, bytes, nibbles;
  ip = ip.split(/%/)[0];

  switch (net.isIP(ip)) {
    case 4:
      bytes = ip.split('.').map(function(o) {
        return parseInt(o, 10);
      });
      bytes.reverse();
      reverseip = bytes.join('.') + '.IN-ADDR.ARPA';
      break;
    case 6:
      nibbles = [];
      ipv6ToBytes(ip).forEach(function(b) {
        nibbles.push(((b >> 4) & 0xf).toString(16));
        nibbles.push((b & 0xf).toString(16));
      });
      nibbles.reverse();
      reverseip = nibbles.join('.') + '.IP6.ARPA';
      break;
  }

  return reverseip;
};
