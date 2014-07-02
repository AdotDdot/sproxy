sproxy
======

Simple customizable interception proxy written in python using the socket module.
Capable of intercepting https traffic generating certificates on the fly.

Setting up
==========
Run *sproxy-setup.py*. It will set up the needed directories and files and create the self-signed CA certificate. The serial number of the certificate can be specified when running the script.

    python sproxy-setup.py [certserial]
    
In order to allow https interception, you will need to register Sproxy as a trusted certificate authority in your browser.

Example usage
=============
The proxy can be launched with default options from the command line. By default is simply prints the first line of each request and response. The default port is 50007. You will need to provide the local certificates file. It defaults to */etc/ssl/certs/ca-certificates.crt*, the most widely used path in Linux systems. 
    
    python sproxy.py [port] [localcertfile]
    

You can alter the requests sent modifying or overriding the Proxy class' method handle_reqs.
For output customization, response parsing etc, you can modify or override the method handle_flow and handle_https_flow.


    from sproxy import Proxy
    class MyProxy(Proxy):
      def handle_reqs(self, request):
        request.set_header('User-Agent', 'sproxy')
        
      def handle_flow(self, request, response, host):
        print 'Got a response from', host
        print response.head
        
    def handle_https_flow(self, request, response, host):
        print 'Got a response over ssl from', host
        print response.head
    
    proxy = MyProxy()
    
    #set some options
    proxy.blacklist = ['www.google.com', 'www.yahoo.com'] 
    proxy.serv_port = 10000
    #change timeouts to alter performance
    proxy.web_timeout = 0.5
    proxy.browser_timeout = 0.5 
    
    #launch proxy
    proxy.start()

Known issues
===========
* Parsing of requests and responses in order to init class instances needs adjusting: initialization unsuccessful in certain cases
* In certain cases an https connection is refused for causes yet not found.


