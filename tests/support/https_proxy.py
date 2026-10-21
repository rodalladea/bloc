"""Synthetic loopback HTTPS reverse proxy for real browser regression fixtures."""
import argparse,http.client,ssl,threading,json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--backends',required=True,help='comma-separated loopback ports')
parser.add_argument('--port',type=int,default=0)
parser.add_argument('--cert',required=True)
parser.add_argument('--key',required=True)
parser.add_argument('--state',required=True)
args=parser.parse_args()
ports=[int(value) for value in args.backends.split(',')]
state={'next':0}
lock=threading.Lock()
class Proxy(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*_): pass
 def do_GET(self): self.forward()
 def do_POST(self): self.forward()
 def forward(self):
  with lock:
   port=ports[state['next']%len(ports)]
   state['next']+=1
  connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
  length=int(self.headers.get('Content-Length','0'))
  if length>16384:
   self.send_error(413)
   return
  body=self.rfile.read(length) if length else None
  headers={key:value for key,value in self.headers.items() if not key.lower().startswith('x-forwarded-') and key.lower() not in ('forwarded','connection','transfer-encoding')}
  headers['X-Forwarded-For']=self.client_address[0]
  headers['X-Forwarded-Proto']='https'
  headers['Connection']='close'
  try:
   connection.request(self.command,self.path,body=body,headers=headers)
   response=connection.getresponse()
   output=response.read()
   self.send_response(response.status)
   for key,value in response.getheaders():
    if key.lower() not in ('connection','content-length','transfer-encoding'):
     self.send_header(key,value)
   self.send_header('Content-Length',str(len(output)))
   self.send_header('Connection','close')
   self.end_headers()
   self.wfile.write(output)
  except (OSError,http.client.HTTPException):
   self.send_error(502)
  finally:
   connection.close()
server=ThreadingHTTPServer(('127.0.0.1',args.port),Proxy)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert,args.key)
server.socket=context.wrap_socket(server.socket,server_side=True)
Path(args.state).write_text(json.dumps({'port':server.server_port,'backends':ports}))
print('HTTPS proxy ready',server.server_port,flush=True)
server.serve_forever()
