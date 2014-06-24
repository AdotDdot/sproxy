#!/usr/bin/env python
#
# sproxy.py
# Copyright (C) 2014 by A.D. <adotddot1123@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# For the terms of the GNU General Public License, see <http://www.gnu.org/licenses/>.
#

import socket
import sys
import threading
import time

class Proxy:
	def __init__(self, serv_port = 50007, certfile = "/etc/ssl/certs/ca-certificates.crt"):
		self.serv_host = ''
		self.serv_port = serv_port
		self.blacklist = []
		self.browser_timeout = 1
		self.web_timeout = 1
		self.buffer_size = 4096
		self.debug = False
		self.certfile = certfile
		self.stdout_lock = threading.Lock()

	def handle_reqs(self, request):
		self.stdout_lock.acquire()
		print '\n'+str(time.time()), '\t'+self._color_code('okgreen', request.first_line)
		self.stdout_lock.release()
		return request	#do not change this line

	def handle_resps(self, response, host):
		self.stdout_lock.acquire()
		print '\n'+str(time.time()), '\t'+self._color_code('okblue', host+': '+response.first_line)
		self.stdout_lock.release()

	def start(self):
		try:
			serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv_sock.bind((self.serv_host, self.serv_port))
			serv_sock.listen(200)
			print 'Proxy running on port', self.serv_port, ': listening'	
		except socket.error, (value, message):
			print self._color_code('fail', 'Could not open socket: error '+str(value)+' - '+message)
			sys.exit(1)
		#mainloop
		while True:
			conn, addr = serv_sock.accept()
			self._log('server connected by '+str(addr))
			conn_thread = threading.Thread(target = self._handle_conn, args = (conn,))
			try: conn_thread.start()
			except: conn.close()
		serv_sock.close()

	def _handle_conn(self, conn):	
		conn.settimeout(self.browser_timeout)
		request = self._recv_pipe(conn)	
		if not request:
			self._log('no request: closing')
			conn.close()
			sys.exit(1)	
		#process request to allow for user changes
		request_obj = HTTPRequest(request)
		http_host, http_port = request_obj.headers['Host'], 80
		request_obj = self.handle_reqs(request_obj)
		request = request_obj.make_raw()	
		self._log('got host '+http_host+', port '+str(http_port))
		#check blacklist
		if http_host in self.blacklist:
			self._log('host in blacklist: closing')
			conn.close()
			sys.exit(1) 
		tunneling = request_obj.method == 'CONNECT'
		#get and send response
		self._send_resp(http_host, http_port, conn, request, tunneling)
		conn.close()
				
	def _send_resp(self, host, port, conn, req, tunneling):
		if tunneling: port = 443
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._log('client to host '+host+' initialized')
		wclient.settimeout(self.web_timeout)
		try:
			hostip = socket.gethostbyname(host)
			wclient.connect((hostip, port))
			self._log('client to host '+host+' connected')
		except socket.timeout:
			print self._color_code('fail', '\nImpossible to connect to '+host+': socket timed out')
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (value, message):
			print self._color_code('fail', '\nSocket error '+str(value)+' '+message+' on '+host)
			wclient.close()
			conn.close()
			sys.exit(1)
		if tunneling: 
			conn.send(b'HTTP/1.1 200 Connection estabilished\n\n')
			self._log('connection estabilished')
			req = self._recv_pipe(conn)
                while 1:
		        wclient.send(req)
		        self._log('request sent to host '+host)
		        response = self._recv_pipe(wclient, conn)
                        if not response: break
			elif not tunneling:
			        response_obj = HTTPResponse(response)
			        self.handle_resps(response_obj, host)	
                        req = self._recv_pipe(conn)
                        if not req: break
			elif not tunneling:
				req_obj = HTTPRequest(req)
				self.handle_reqs(req_obj)
		wclient.close()
		self._log('connection to client and connection to host '+host+' closed')

	def _recv_pipe(self, from_conn, to_conn = ''):
		msg = []
		gotnull = 0
		while True:
			try:
				msg_pack = from_conn.recv(self.buffer_size)
			except socket.timeout:
				self._log('timeout on receiving data packet: breaking loop')
				break
			if not msg_pack:
				if gotnull: self._log('no more data: breaking loop'); break
				else: gotnull = 1
			else:
				self._log('got data packet of len '+str(len(msg_pack)))
				msg.append(msg_pack)
				if to_conn:
					try: to_conn.send(msg_pack)
					except socket.error, (value, message):
						print self._color_code('fail', '\nImpossible to send response: got error '+str(value)+' - '+message)
						from_conn.close()
						to_conn.close()
						sys.exit(1)
		return b''.join(msg)

	def _log(self, line):
		if self.debug: print line
		else: pass

	def _color_code(self, code, line):
		line = str(line)	
		if not sys.stdout.isatty(): return line
		else:
			endb = "\033[0m"
			if code == 'fail': return '\033[1;91m'+line+endb
			elif code == 'warn': return '\033[1;93m'+line+endb
			elif code == 'okgreen': return '\033[1;92m'+line+endb
			elif code == 'okblue': return '\033[1;94m'+line+endb
			elif code == 'pblue': return '\033[94m'+line+endb
			elif code == 'pgreen': return '\033[92m'+line+endb
			elif code == 'pyell': return '\033[93m'+line+endb
			else: return line


class HTTPRequest:
	def __init__(self, raw_req):
		self.raw = raw_req
		self._set_parts()

	def _set_parts(self):
		self.head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').split('\n\n')[0])
		self.body = self.raw.replace(self.head.encode(), b'').replace(b'\n\n', b'')
		self.first_line = self.head.splitlines()[0]
		self.headers = dict([x.split(': ', 1) for x in self.head.splitlines()[1:]])
		self.method, self.url, self.protov = self.first_line.split(' ', 2)
		return (self.head, self.body, self.first_line, self.headers, self.method, self.url, self.protov)

	def set_header(self, header, value):
		self.headers[header] = value

	def make_raw(self):
		first_line = ' '.join([self.method, self.url, self.protov])
		headers = '\n'.join([header+': '+self.headers[header] for header in self.headers])
		head = '\n'.join([first_line, headers])
		return b'\n\n'.join([head.encode(), self.body])


class HTTPResponse:
	def __init__(self, raw_resp):
		self.raw = raw_resp
		self.head, self.body, self.first_line, self.headers, self.proto, self.status, self.status_text = self._set_parts()

	def _set_parts(self):
		head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').split('\n\n')[0])
		body = self.raw.replace(head.encode(), b'').replace(b'\n\n', b'')
		first_line = head.splitlines()[0]
		headers = dict(x.split(': ', 1) for x in head.splitlines()[1:])
		proto, status, status_text = first_line.split(' ', 2)
		return (head, body, first_line, headers, proto, status, status_text)	


if __name__ == '__main__':
  serv_port = int(sys.argv[1]) if len(sys.argv) > 1 else 50007
  proxy = Proxy()
  proxy.start()
