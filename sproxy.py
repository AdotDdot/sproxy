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
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket
import sys
import threading
import ssl
import os
from OpenSSL import crypto
from codict import COD as HeaderDict

class Proxy:
	def __init__(self, serv_port = 50007):
		self.serv_host = ''
		self.serv_port = serv_port
		self.max_listen = 300
		self.blacklist = []
		self.browser_timeout = 1
		self.web_timeout = 1
		self.buffer_size = 4096
		self.debug = False
		self.stdout_lock = threading.Lock()
		self._certfactory = CertFactory()
		self._init_localcert()

	def handle_reqs(self, request):
		pass

	def handle_flow(self, request, response, host):
		clength = str(response.headers['Content-Length'])+' bytes' if 'Content-Length' in response.headers else ''
		ctype = response.headers['Content-Type'] if 'Content-Type' in response.headers else ''
		self.stdout_lock.acquire()
		print '\n'+self._color_code('okgreen', request.first_line)
		print '  '+self._color_code('okblue', response.first_line+'  '+clength+'  '+ctype)
		self.stdout_lock.release()

	def handle_https_flow(self, request, response, host):
		clength = str(response.headers['Content-Length'])+' bytes' if 'Content-Length' in response.headers else ''
		ctype = response.headers['Content-Type'] if 'Content-Type' in response.headers else ''
		url = 'https://'+host+request.url
		self.stdout_lock.acquire()
		print '\n'+self._color_code('warn', request.first_line.replace(request.url, url, 1))
		print '  '+self._color_code('okblue', response.first_line+'  '+clength+'  '+ctype)
		self.stdout_lock.release()
		
	def start(self):
		try:
			serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			serv_sock.bind((self.serv_host, self.serv_port))
			serv_sock.listen(self.max_listen)
			print 'Proxy running on port', self.serv_port, ': listening'	
		except socket.error, (value, message):
			print self._color_code('fail', 'Could not open socket: error '+str(value)+' - '+message)
			sys.exit(1)
		#mainloop
		while True:
			try:
				conn, addr = serv_sock.accept()
				self._log('server connected by '+str(addr))
				conn_thread = threading.Thread(target = self._handle_conn, args = (conn,))
				conn_thread.daemon = 1
				try: conn_thread.start()
				except: conn.close()
			except KeyboardInterrupt:
				if conn: conn.close()
				serv_sock.close()
				print "\n"
				exit(0)

	def _handle_conn(self, conn):	
		conn.settimeout(self.browser_timeout)
		request = self._recv_pipe(conn)	
		if not request:
			self._log('no request: closing')
			conn.close()
			sys.exit(1)	
		#process request to allow for user changes
		request_obj = HTTPRequest(request)
		self.handle_reqs(request_obj)
		request = request_obj.make_raw()
		tunneling = request_obj.method == 'CONNECT'
		http_port = 443 if tunneling else 80
		http_host = request_obj.headers['Host']
		self._log('got host '+http_host+', port '+str(http_port))
		#check blacklist
		if http_host in self.blacklist:
			self._log('host in blacklist: closing')
			conn.close()
			sys.exit(1) 		
		#get and send response
		if tunneling: self._https(http_host, http_port, conn)
		else: self._send_resp(http_host, http_port, conn, request, request_obj)
		conn.close()

	def _https(self, host, port, conn):
		conn.send(b'HTTP/1.1 200 Connection estabilished\n\n')
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		wclient = ssl.wrap_socket(wclient, server_side = False, ca_certs = self.certfile, cert_reqs = ssl.CERT_REQUIRED)
		try: wclient.connect((host, port))
		except ssl.SSLError, m: 
			print self._color_code('fail', '\nCould not connect to', host, m)
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			print self._color_code('fail', '\nCould not connect to:', host, 'socket error', v, m)
			wclient.close()
			conn.close()
			sys.exit(1)
		wclient.settimeout(self.web_timeout)
		#get server's certificate as pem 
		pem_data = ssl.DER_cert_to_PEM_cert(wclient.getpeercert(binary_form = True))	
		certfile, keyfile = self._certfactory.make_cert(pem_data)
		try: conn = ssl.wrap_socket(conn, server_side = True, certfile = certfile, keyfile= keyfile)
		except ssl.SSLError, m: 
			self._log('Could not complete ssl handshacke with client:', m)
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			self._log('socket error: '+str(v)+' '+m)
			wclient.close()
			conn.close()
			sys.exit(1)
		#get plain text data
		request = self._recv_pipe(conn)
		if not request:
			wclient.close()
			conn.close()	
			sys.exit(1)	
		request_obj = HTTPRequest(request)
		self.handle_reqs(request_obj)
		request = request_obj.make_raw()
		wclient.send(request)
		try: 
			response = self._recv_pipe(wclient, conn)
			if response: 
				response_obj = HTTPResponse(response)
				self.handle_https_flow(request_obj, response_obj, host)
		except ssl.SSLError, m: self._log(str(m))
		except socket.error, (v, m): self._log(host+ ' - Error '+str(v)+' '+m)
		finally:
			wclient.close()
			conn.close()
		
	def _send_resp(self, host, port, conn, req, req_obj):
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
		wclient.send(req)
		self._log('request sent to host '+host)
		response = self._recv_pipe(wclient, conn)
		if response:
			response_obj = HTTPResponse(response)
			self.handle_flow(req_obj, response_obj, host)					
		wclient.close()
		self._log('connection to client and connection to host '+host+' closed')

	def _recv_pipe(self, from_conn, to_conn = ''):
		msg = []
		gotnull = 0
		while True:
			try:
				msg_pack = from_conn.recv(self.buffer_size)
			except ssl.SSLError, m:
				self._log('ssl error '+str(m))
				break
			except socket.timeout:
				self._log('timeout on receiving data packet: breaking loop')
				break
			except socket.error, (v, m):
				self._log('socket error '+str(v)+' '+m)
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
						self._log('Impossible to send response: got error ', value, '-', message)
						from_conn.close()
						to_conn.close()
						sys.exit(1)
		return b''.join(msg)
	
	def _init_localcert(self):
		with open(os.path.join('sproxy_files', 'localcerts.txt'), 'rt') as loc:
			self.certfile = loc.read()

	def _log(self, *args):
		if self.debug: print ' '.join([str(arg) for arg in args])
		else: pass

	def _color_code(self, code, *args):
		line = ' '.join([str(arg) for arg in args])	
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
			elif code == 'bmag': return '\033[1;95m'+line+endb
			elif code == 'pcyan': return '\033[37m'+line+endb
			else: return line


class HTTPRequest:
	def __init__(self, raw_req):
		self.raw = raw_req
		self._set_parts()

	def _set_parts(self):
		try: self.head, self.body = self.raw.replace(b'\r\n\r\n', b'\n\n').replace(b'\n\r\n\r', b'\n\n').split('\n\n', 2)
		except ValueError: 
			self.head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').replace(b'\n\r\n\r', b'\n\n')).split('\n\n', 2)[0]
			self.body = self.raw.replace(self.head.encode(), b'')	
		self.first_line = str(self.head).splitlines()[0] if self.head else ''
		self.headers = HeaderDict([x.split(': ', 1) for x in self.head.splitlines()[1:]]) if self.head else {}
		if self.first_line: self.method, self.url, self.protov = self.first_line.split(' ', 2)
		else:
			self.method = ''
			self.url = ''
			self.protov = ''
		return (self.head, self.body, self.first_line, self.headers, self.method, self.url, self.protov)

	def set_header(self, header, value):
		self.headers[header] = value
		headers = '\n'.join([header+': '+self.headers[header] for header in self.headers])
		self.head = '\n'.join([self.first_line, headers])
		
	def make_raw(self):
		first_line = ' '.join([self.method, self.url, self.protov])
		headers = '\r\n'.join([header+': '+self.headers[header] for header in self.headers])
		head = '\r\n'.join([first_line, headers])
		return b'\r\n\r\n'.join([head.encode(), self.body])


class HTTPResponse:
	def __init__(self, raw_resp):
		self.raw = raw_resp
		self.head, self.body, self.first_line, self.headers, self.proto, self.status, self.status_text = self._set_parts()

	def _set_parts(self):
		head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').replace(b'\n\r\n\r', b'\n\n')).split('\n\n', 2)[0]
		body = self.raw.replace(head.encode(), b'')
		first_line = head.splitlines()[0]
		headers = HeaderDict(x.split(': ', 1) for x in head.splitlines()[1:])
		proto, status, status_text = first_line.split(' ', 2)
		return (head, body, first_line, headers, proto, status, status_text)	


class CertFactory:
	def __init__(self):
		self._files_dir = 'sproxy_files'
		self._sid = os.path.join(self._files_dir,'sid.txt')
		with open(self._sid, 'rt') as sid: self._count = int(sid.read())
		self._count_lock = threading.Lock()
		self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(os.path.join(self._files_dir, 'sproxy.pem')).read())
		self.root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(os.path.join(self._files_dir, 'sproxy.key')).read())
		self.issuer= self.root_cert.get_subject()
			
	def make_cert(self, pem_data):
		old_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
		common_name = old_cert.get_subject().CN	
		if os.path.isfile(os.path.join(self._files_dir, common_name+'.pem')):
			certfile = os.path.join(self._files_dir, common_name+'.pem')
			keyfile = os.path.join(self._files_dir, common_name+'.key')
			return certfile, keyfile
		pkey = crypto.PKey()
		pkey.generate_key(crypto.TYPE_RSA, 2048)
		new_cert = crypto.X509()
		new_cert.gmtime_adj_notBefore(0)
		new_cert.gmtime_adj_notAfter(10*365*24*60*60)
		#set same subject of old cert
		new_cert.set_subject(old_cert.get_subject())
		#look for and set SNA of old cert
		for i in range(old_cert.get_extension_count()):
			ext = old_cert.get_extension(i)
			if ext.get_short_name() == 'subjectAltName':
				new_cert.add_extensions([ext])
		new_cert.set_issuer(self.issuer)
		self._count_lock.acquire()
		new_cert.set_serial_number(self._count)
		self._count += 1
		self._count_lock.release()		
		new_cert.set_pubkey(pkey)
		new_cert.sign(self.root_key, 'sha1')
		certfile = os.path.join( self._files_dir, common_name+'.pem',)
		keyfile = os.path.join( self._files_dir, common_name+'.key')		
		#write key and cert
		with open(certfile, "wt") as cf: cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, new_cert))
		with open(keyfile, "wt") as kf: kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
		#append root to cert chain
		with open(certfile, 'at') as ccf: ccf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.root_cert)) 		
		return certfile, keyfile

	def __del__(self):
		with open(self._sid, 'wt') as sid:
			self._count_lock.acquire()
			sid.write(str(self._count))
			self._count_lock.release()


if __name__ == '__main__':
  serv_port = int(sys.argv[1]) if len(sys.argv) > 1 else 50007
  certfile = sys.argv[2] if len(sys.argv) > 2 else "/etc/ssl/certs/ca-certificates.crt"
  proxy = Proxy(serv_port, certfile)
  proxy.browser_timeout = 1
  proxy.start()
