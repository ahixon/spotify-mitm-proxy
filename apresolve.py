import SimpleHTTPServer
import SocketServer
import json

PORT = 80

class APHandler (SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET (self):
		self.send_response (200)
		self.send_header ('Content-Type', 'application/json; charset=utf-8')
		self.end_headers()

		self.wfile.write (json.dumps ({"ap_list":["localhost:4070"]}))

httpd = SocketServer.TCPServer(("", PORT), APHandler)

print "serving at port", PORT
try:
	httpd.allow_reuse_address = True
	httpd.serve_forever()
except KeyboardInterrupt:
	httpd.shutdown()