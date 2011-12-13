#!/usr/bin/env python
"""
ClientCertHTTPProxy is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

ClientCertHTTPProxy is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
ClientCertHTTPProxy.  If not, see <http://www.gnu.org/licenses/>.

Copyright (C) 2011 Christopher Schwardt <nookieman@gmx.de>
"""

from Cookie import BaseCookie
import httplib
import urllib2
from twisted.internet import reactor, ssl
from twisted.web.http import HTTPChannel, HTTPFactory, Request

KEYFILE = None
CERTFILE = None

class HTTPSClientCertHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(host, key_file=self.key, cert_file=self.cert)


class ClientCertRequest(Request):

    def __init__(self, *args, **kwargs):
        self.key = KEYFILE
        self.cert = CERTFILE
        self.opener = urllib2.build_opener(HTTPSClientCertHandler(self.key, self.cert))
        Request.__init__(self, *args, **kwargs)

    def proxyRequest(self):
        url = self.uri
        header = self.requestHeaders
        data = None
        if self.method.lower() == "post":
            data = self.content.read()
        return self.proxy(url, header, data)

    def proxy(self, url, header=None, data=None):
#        print "proxy('%s', '%s', '%s')" % (url, header, data)
        url = url.replace('http://', 'https://')
        headers = {}
        if header:
            for key, val in header.getAllRawHeaders():
                if not key.startswith("Proxy") and not key == "Accept-encoding":
                    for value in val:
                        headers[key] = value
        request = urllib2.Request(url=url, data=data, headers=headers)
        return self.opener.open(request)

    def generateResponseText(self, response):
        content = response.read()
        return content

    def prepareResponse(self, response):
        for key, value in response.headers.items():
            if key.lower() == "set-cookie":
                cookie = BaseCookie(value)
                # use all attributes but 'secure', because then the browser won't send the cookie anymore
                value = cookie.output(attrs=['expires','path','comment','domain','max-age','secure','version','httponly'], header="")
            self.setHeader(key, value)
        self.setResponseCode(response.code)

    def process(self):
        try:
            response = self.proxyRequest()
        except urllib2.HTTPError, e:
            response = e
        responseText = self.generateResponseText(response)
        self.prepareResponse(response)
        self.write(responseText)
        self.finish()


class HTTPSClientCertProxyChannel(HTTPChannel):

    requestFactory = ClientCertRequest


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="""HTTP proxy that uses a given client certificate to authenticate all proxied
requests with the server.
Notice, that all requests have to be http, even if the target is https.
All requests will be rewritten to https.""")
    parser.add_argument('-c', '--cert', dest="cert", type=str, required=True,
                        help="The certificate to use in pem format.")
    parser.add_argument('-k', '--key', dest="key", type=str, required=True,
                        help="The private key to use in pem format.")
    parser.add_argument('-p', '--port', dest='port', type=int, default=8080,
                        help="The port the HTTP proxy listens on (default: 8080).")
    args = parser.parse_args()

    CERTFILE = args.cert
    KEYFILE = args.key

    httpFactory = HTTPFactory()
    httpFactory.protocol = HTTPSClientCertProxyChannel
    reactor.listenTCP(args.port, httpFactory)
    print "now starting..."
    reactor.run()
