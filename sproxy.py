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
import time
import urlparse
from OpenSSL import crypto
from _abcoll import *
from operator import eq as _eq
from itertools import imap as _imap
try:
    from thread import get_ident as _get_ident
except ImportError:
    from dummy_thread import get_ident as _get_ident


class Proxy:
	def __init__(self, serv_port):
		self.serv_host = ''
		self.serv_port = serv_port
		self.max_listen = 300
		self.debug = False
		self.browser_timeout = 0.5
		self.web_timeout = 0.5
		self.buffer_size = 4096
		self._stdout_lock = threading.Lock()
		self._certfactory = CertFactory()
		self._init_localcert()
		
	def modify_all(self, request):
		'''Override to apply changes to every request'''
		pass

	def parse_response(self, response, host):
		'''Override to handle received response - best used with concurrency'''
                pass

	def output_flow(self, request, response):
		'''Override to change output'''
		print '\n'+request.first_line
		print response.first_line    

	def start(self):
		'''Start the proxy server'''
		try:
			serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			serv_sock.bind((self.serv_host, self.serv_port))
			serv_sock.listen(self.max_listen)
			cname = serv_sock.getsockname()
                        time.sleep(0.5)
			print '\nProxy running on port %d - listening'%self.serv_port
		except socket.error, (value, message):
			self._log(cname, 'Could not open server socket: error %d %s'%(value,message))
			sys.exit(1)
		#mainloop
		while True:
			try:
				conn, addr = serv_sock.accept()
				self._log(cname, 'server connected by %s %s'%addr)
				conn_thread = threading.Thread(target = self._handle_conn, args = (conn,))
				conn_thread.daemon = 1
				try: conn_thread.start()
				except: conn.close()
			except KeyboardInterrupt:
				if conn: conn.close()
				self._certfactory.cleanup()
				serv_sock.close()
				exit(0)

	def _init_localcert(self):
		with open(os.path.join('sproxy_files', 'localcerts.txt'), 'rt') as loc:
			self.certfile = loc.read()

	def _handle_conn(self, conn):	
		#get request from browser
		conn.settimeout(self.browser_timeout)
                cname = conn.getsockname()
		request = self._recv_pipe('browser', conn)	
		if not request:
			self._log(cname, 'no request received from browser: closing socket')
			conn.close()
			sys.exit(1)	
		#process request to allow for user changes
		request_obj = HTTPRequest(request)
		self._handle_reqs(request_obj)
		request = request_obj.whole
		tunneling = request_obj.method == 'CONNECT'
		http_port = 443 if tunneling else 80
		http_host = request_obj.headers['Host']
		self._log(cname, 'got host %s, port %d'%(http_host, http_port))		
		#get and send response
		if tunneling: self._get_https_resp(http_host, http_port, conn)
		else: 
                        self._get_http_resp(http_host, http_port, conn, request, request_obj)
		conn.close()

	def _get_https_resp(self, host, port, conn):
                cname = conn.getsockname()
		conn.send(b'HTTP/1.1 200 Connection estabilished\n\n')
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		wclient = ssl.wrap_socket(wclient, server_side = False, ca_certs = self.certfile, cert_reqs = ssl.CERT_REQUIRED)
		try: wclient.connect((host, port))
		except ssl.SSLError, m: 
			self._log(cname, 'could not connect to %s: %s'%(host, m))
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			self._log(cname, 'could not connect to %s: socket error %d %s'%(host, v, m))
			wclient.close()
			conn.close()
			sys.exit(1)
		wclient.settimeout(self.web_timeout)
		#get server's certificate as pem 
		pem_data = ssl.DER_cert_to_PEM_cert(wclient.getpeercert(binary_form = True))	
		certfile, keyfile = self._certfactory.make_cert(pem_data)
		try: conn = ssl.wrap_socket(conn, server_side = True, certfile = certfile, keyfile= keyfile)
		except ssl.SSLError, m: 
			self._log(cname, 'could not complete ssl handshacke with browser client: %s'%m)
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			self._log(cname, ('could not complete ssl handshake with browser client: socket error %d - %s'%(v, m)))
			wclient.close()
			conn.close()
			sys.exit(1)
		#get plain text data
		request = self._recv_pipe(host, conn)
		if not request:
			wclient.close()
			conn.close()	
			sys.exit(1)	
		request_obj = HTTPRequest(request, https=True)
		self._handle_reqs(request_obj)
		request = request_obj.whole
		wclient.send(request)
		response = self._recv_pipe(host, wclient, conn)
		if response: 
			response_obj = HTTPResponse(response)
			self._handle_response(request_obj, response_obj, host)
		wclient.close()
		conn.close()
		
	def _get_http_resp(self, host, port, conn, req, req_obj):
                cname = conn.getsockname()
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._log(cname, 'client to host %s initialized'%host)
		wclient.settimeout(self.web_timeout)
		try:
			wclient.connect((host, port))
			self._log(cname, 'client to host %s connected'%host)
		except socket.timeout:
			self._log(cname, 'could not connect to %s: socket timed out'%host)
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (value, message):
			self._log(cname, 'could not connect to %s: socket error error %d %s'%(host, value, message))
			wclient.close()
			conn.close()
			sys.exit(1)
		wclient.send(req)
		self._log(cname, 'request sent to host %s'%host)
		response = self._recv_pipe(host, wclient, conn)
		if response:
			response_obj = HTTPResponse(response)
			self._handle_response(req_obj, response_obj, host)					
		wclient.close()
		self._log(cname, 'connection to client and connection to host %s closed'%host)

	def _recv_pipe(self, source, from_conn, to_conn = ''):
		msg = []
                cname = from_conn.getsockname()
		gotnull = 0
		while True:
			try:
				msg_pack = from_conn.recv(self.buffer_size)
			except ssl.SSLError, m:
				self._log(cname, 'ssl error occured while receiving data from %s: %s'%(source, m))
				break
			except socket.timeout:
				break
			except socket.error, (v, m):
				self._log(cname, 'socket error %d occurred while receiving data from %s - %s'%(v, source, m))
				break
			if not msg_pack:
				if gotnull: 
					break
				else: gotnull = 1
			else:
				msg.append(msg_pack)
				if to_conn:
					try: to_conn.send(msg_pack)
					except socket.error, (value, message):
						self._log(cname, 'could not send response from %s to %s: socket error %d - %s'%(source, (to_conn.getsockname()), value, message))
						from_conn.close()
						to_conn.close()
						sys.exit(1)
		return b''.join(msg)

	def _log(self, cname, content):
                if self.debug: 
			self._stdout_lock.acquire()
			print '%f  '%time.time(), ('[%s %d]'%cname).ljust(25), content
			self._stdout_lock.release()

	def _handle_reqs(self, request):
		#apply changes
		self.modify_all(request)
		#reset request
		request.whole = request.make_raw()
		       
	def _handle_response(self, request, response, host):
		'''After response has been received'''
		self._stdout_lock.acquire()
                self.output_flow(request, response)
		self._stdout_lock.release()
                self.parse_response(response, host)

                         
class HTTPRequest:
	def __init__(self, raw_req, https = False):
		self.https = https
		self.on_hold = False
		self.whole = raw_req.replace('\r', '\n').replace('\n\n', '\n')
		self._set_parts()
		self._decode_body()

	def _set_parts(self):
                self.head, self.body = self.whole.split('\n\n')
		self.first_line = str(self.head).splitlines()[0]
		self.headers = HeaderDict([x.split(': ', 1) for x in self.head.splitlines()[1:]])
                self.method, self.url, self.protov = self.first_line.split(' ', 2)
		if self.https: self.url = 'https://'+self.headers['host']+self.url

	def _decode_body(self): 
		if self.body and 'Content-Type' in self.headers and 'application/x-www-form-urlencoded' in self.headers['Content-Type']:
			self.decoded_body = '\n'.join(['[Url-encoded]']+[': '.join(t) for t in urlparse.parse_qsl(self.body.strip('\n'))])
		else:
			self.decoded_body = self.body

	def set_header(self, header, value):
		self.headers[header] = value
		headers = '\n'.join([header+': '+self.headers[header] for header in self.headers])
		self.head = '\n'.join([self.first_line, headers])
		
	def make_raw(self):
		#put all parts back together
		parsed = urlparse.urlparse(self.url)
		url = self.url.replace(parsed.scheme+'://'+parsed.netloc, '', 1)
		first_line = ' '.join([self.method, url, self.protov])
		headers = '\r\n'.join([header+': '+self.headers[header] for header in self.headers])
		head = '\r\n'.join([first_line, headers]) 
		return '\r\n\r\n'.join([head, self.body]) 


class HTTPResponse:
	def __init__(self, raw_resp):
		self.raw = raw_resp
		self._set_parts()

	def _set_parts(self):
		self.head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').replace(b'\n\r\n\r', b'\n\n')).split('\n\n', 2)[0]
		self.body = self.raw.replace(self.head.encode(), b'').replace('\n\n', '')
		self.first_line = self.head.splitlines()[0]
		self.headers = HeaderDict(x.split(': ', 1) for x in self.head.splitlines()[1:])
		self.protov, self.status, self.status_text = self.first_line.split(' ', 2)


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

	def cleanup(self):
		#update count of last serial number used
		with open(self._sid, 'wt') as sid:
			self._count_lock.acquire()
			sid.write(str(self._count))
			self._count_lock.release()


class HeaderDict(dict):
    '''Caseless Ordered Dictionary
    Enables case insensitive searching and updating while preserving case sensitivity when keys are listed.
    Combination of the code of collections.OrderedDict and CaselessDictionary (https://gist.github.com/bloomonkey/3003096) '''
    
    def __init__(self, *args, **kwds):
        if len(args) > 1:
            raise TypeError('expected at most 1 arguments, got %d' % len(args))
        try:
            self.__root
        except AttributeError:
            self.__root = root = []                   
            root[:] = [root, root, None]
            self.__map = {}
        self.__update(*args, **kwds)

    def __contains__(self, key):
        return dict.__contains__(self, key.lower())
  
    def __getitem__(self, key):
        return dict.__getitem__(self, key.lower())['val'] 

    def __setitem__(self, key, value, dict_setitem=dict.__setitem__):
        if key not in self:
            root = self.__root
            last = root[0]
            last[1] = root[0] = self.__map[key] = [last, root, key]
        return dict.__setitem__(self, key.lower(), {'key': key, 'val': value})

    def __delitem__(self, key, dict_delitem=dict.__delitem__):
        dict_delitem(self, key)
        link_prev, link_next, _ = self.__map.pop(key)
        link_prev[1] = link_next                        
        link_next[0] = link_prev                       

    def __iter__(self):
        root = self.__root
        curr = root[1]                                  
        while curr is not root:
            yield curr[2]                              
            curr = curr[1]                         

    def __reversed__(self):
        root = self.__root
        curr = root[0]                                
        while curr is not root:
            yield curr[2]                             
            curr = curr[0]                       

    def clear(self):
        root = self.__root
        root[:] = [root, root, None]
        self.__map.clear()
        dict.clear(self)

    def keys(self):
        return list(self)

    def values(self):
        return [self[key] for key in self]

    def items(self):
        return [(key, self[key]) for key in self]

    def iterkeys(self):
        return iter(self)

    def itervalues(self):
        for k in self:
            yield self[k]

    def iteritems(self):
        for k in self:
            yield (k, self[k])

    def get(self, key, default=None):
        try:
            v = dict.__getitem__(self, key.lower())
        except KeyError:
            return default
        else:
            return v['val']

    def has_key(self,key):
        return key in self

    update = MutableMapping.update

    __update = update 

    __marker = object()

    def pop(self, key, default=__marker):
        if key in self:
            result = self[key]
            del self[key]
            return result
        if default is self.__marker:
            raise KeyError(key)
        return default

    def setdefault(self, key, default=None):
        if key in self:
            return self[key]
        self[key] = default
        return default

    def popitem(self, last=True):
        if not self:
            raise KeyError('dictionary is empty')
        key = next(reversed(self) if last else iter(self))
        value = self.pop(key)
        return key, value

    def __repr__(self, _repr_running={}):
        call_key = id(self), _get_ident()
        if call_key in _repr_running:
            return '...'
        _repr_running[call_key] = 1
        try:
            if not self:
                return '%s()' % (self.__class__.__name__,)
            return '%s(%r)' % (self.__class__.__name__, self.items())
        finally:
            del _repr_running[call_key]

    def __reduce__(self):
        items = [[k, self[k]] for k in self]
        inst_dict = vars(self).copy()
        for k in vars(OrderedDict()):
            inst_dict.pop(k, None)
        if inst_dict:
            return (self.__class__, (items,), inst_dict)
        return self.__class__, (items,)

    def copy(self):
        return self.__class__(self)

    @classmethod
    def fromkeys(cls, iterable, value=None):
        self = cls()
        for key in iterable:
            self[key] = value
        return self

    def __eq__(self, other):
        if isinstance(other, OrderedDict):
            return dict.__eq__(self, other) and all(_imap(_eq, self, other))
        return dict.__eq__(self, other)

    def __ne__(self, other):
        return not self == other

    def viewkeys(self):
        return KeysView(self)

    def viewvalues(self):
        return ValuesView(self)

    def viewitems(self):
        return ItemsView(self)


if __name__ == '__main__':
	serv_port = int(sys.argv[1]) if len(sys.argv) > 1 else 50007
	proxy = Proxy(serv_port)
	proxy.start()
