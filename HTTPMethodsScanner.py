#!/usr/bin/env python
import argparse
from urllib.parse import urlparse
from functools import partial
from multiprocessing.pool import ThreadPool
import http.client as httpclient
import ssl

def send_connections(f, url, method):	
	if url.scheme == 'http':
		conn = httpclient.HTTPConnection(url.netloc)
	elif url.scheme == 'https':
		conn = httpclient.HTTPSConnection(url.netloc, context=ssl._create_unverified_context())

	conn.request(method, url.path)
	resp = conn.getresponse()
	content = resp.read()

	if resp.status == 200 or resp.status == 301:
		print(method + ' ' + str(resp.status))
		# f.write(method + ' ' + str(resp.status) + "\n")

		if method == 'OPTIONS':
			allow_header = resp.getheader('Allow')
			if allow_header is not None:
				print(' - ' + allow_header)
			# f.write(allow_header + "\n")




parser = argparse.ArgumentParser(description='Scan some HTTP methods')
parser.add_argument('--url', metavar='url', help='The full URL with params. (e.g. http://www.foo.com:80/bar/test.html')
args = parser.parse_args()


http_methods = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'VERSION-CONTROL', 'REPORT', 'CHECKOUT', 'CHECKIN', 'UNCHECKOUT', 'MKWORKSPACE', 'UPDATE', 'LABEL', 'MERGE', 'BASELINE-CONTROL', 'MKACTIVITY', 'ORDERPATCH', 'ACL', 'PATCH', 'SEARCH', 'BCOPY', 'BDELETE', 'BMOVE', 'BPROPFIND', 'BPROPPATCH', 'NOTIFY', 'POLL', 'SUBSCRIBE', 'UNSUBSCRIBE', 'X-MS-ENUMATTS']


url = urlparse(args.url)

print('This script will only show those HTTP Methods with response codes of 200 or 301')
print('===============================================================================')

# f = open('test.txt', 'w')
f = None
results = ThreadPool(7).map(partial(send_connections, f, url), http_methods)



