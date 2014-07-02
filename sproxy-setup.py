#!/usr/bin/env python
#
# sproxy-setup.py
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

from OpenSSL import crypto 
import os
from sys import argv

serial = int(argv[1]) if len(argv) > 1 else 1

#make cache directory
cache_dir = 'sproxy_files'
if not os.path.isdir(cache_dir): os.mkdir(cache_dir)

#make sid file in cache directory to store last used serial number
sid_file = os.path.join('sproxy_files', 'sid.txt')
if not os.path.isfile(sid_file):
	sid = open(sid_file, 'w')
	sid.write('0')
	sid.close()

#make root certificates in cache directory
CERT_FILE = os.path.join(cache_dir, "sproxy.pem")
KEY_FILE = os.path.join(cache_dir, "sproxy.key")
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)
cert = crypto.X509()
cert.get_subject().O = "Sproxy"
cert.get_subject().OU = 'Sproxy Root CA'
cert.get_subject().CN = 'Sproxy Root CA'
cert.set_serial_number(serial)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10*365*24*60*60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha1')

with open(CERT_FILE, "wt") as cf: cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
with open(KEY_FILE, "wt") as kf: kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
