sproxy
======

Simple customizable http proxy written in python using the socket module.


Example usage
=============
The proxy can be launched with default options from command line. By default is simply prints the first line of each request and response. The default port is 50007.
    
    python sproxy.py [port] [certfile]
    
The proxy is capable of browsing over https, but it isn't possible to view or modify ssl traffic (yet).
If browsing over https, it is necessary to init the proxy providing the local certificates file. It defaults to */etc/ssl/certs/ca-certificates.crt*, the most widely used path in Linux systems. 

To customize requests and response handling, override the Proxy class' handle_reqs and handle_resps methods. The method handle_reqs accepts as argument a HTTPRequest class instance and also allows for modifications of requests. The method handle_resps accepts as arguments a HTTPResponse class instance and the response host.


    from sproxy import Proxy
    class MyProxy(Proxy):
      def handle_reqs(self, request):
        request.set_header('User-Agent', 'Python Proxy') #modify request header
        print request.first_line
        
      def handle_resps(self, response, host):
        print 'Got a response from', host
        print response.head
    
    proxy = MyProxy()
    
    #set some options
    proxy.blacklist = ['www.google.com', 'www.yahoo.com'] #blacklist some hosts
    proxy.serv_port = 10000 #modify port
    proxy.web_timeout = 0.5
    proxy.browser_timeout = 0.5 #you can change the timeouts to alter performance
    
    #launch proxy
    proxy.start()



