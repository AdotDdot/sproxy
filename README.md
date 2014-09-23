sproxy
======

Simple customizable interception proxy written in python using the socket module.
Capable of intercepting https traffic generating certificates on the fly.


Setting up
==========
  * Run *sproxy-setup.py*. It will create the needed directories and create the self-signed SSL certificate. You may specify the local certificates file path (defaults to */etc/ssl/certs/ca-certificates.crt*) and the serial number of the self-signed certificate (defaults to 1).
  `python sproxy-setup.py [localcert] [serial]`
  * In the newly-created directory *sproxy_files* you can find the certificate file *sproxy.pem*. Import it in your browser as a trusted certificate authority.
  * Configure your browser to use the proxy and run *sproxy.py*. You can specify the port in the command-line arguments (defaults to 50007).
  `python sproxy.py [port]`

Example usage
=============
The proxy can be launched with default options from the command line. By default is simply prints the first line of each request and response.

Override the Proxy class' methods to customize behaviour. Example:

    from sproxy import Proxy
    class MyProxy(Proxy):
      def modify_all(self, request):
        '''Override to apply changes to every request'''
        request.set_header('user-agent', 'sproxy') #modify header on all oncoming requests
        
      def output_flow(self, request, response):
        '''Override to change output'''
        print request.head #print the whole head of request and response
        print response.head
        
      def parse_response(self, response, host):
        '''Override to handle received response - best used with concurrency'''
        new_thread = threading.Thread(target=user_defined_function) #start a new thread with some newly-defined function
        new_thread.start()
        
    proxy = MyProxy()
    #set some options
    proxy.serv_port = 10000
    proxy.max_listen = 200
    #change timeouts to alter performance
    proxy.web_timeout = 1
    proxy.browser_timeout = 1
    #launch proxy
    proxy.start()

Known issues
===========
* Certain websites require high timeout values when browsing over https.
* Certain hosts return 4xx responses when browsing through the proxy.

