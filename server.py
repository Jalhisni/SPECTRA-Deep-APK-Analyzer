"""Local-only SPECTRA upload server. No external telemetry or sample execution."""
from __future__ import annotations
import argparse, json, mimetypes, os, sys, threading, webbrowser
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from analyzer import APKError
from deep_scan import deep_analyze

ROOT=Path(__file__).resolve().parent
MAX_UPLOAD=120*1024*1024

class Handler(BaseHTTPRequestHandler):
    server_version='SPECTRA/4.0'
    def log_message(self,fmt,*args):
        print('[SPECTRA]',fmt%args)
    def _send(self,status,body,ctype):
        self.send_response(status)
        self.send_header('Content-Type',ctype)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def json(self,status,obj):
        self._send(status,json.dumps(obj,ensure_ascii=False).encode('utf-8'),'application/json; charset=utf-8')
    def do_GET(self):
        path=urlsplit(self.path).path
        files={'/':'static/index.html','/app.js':'static/app.js','/style.css':'static/style.css'}
        if path not in files:
            self.json(404,{'error':'Not found'});return
        p=ROOT/files[path]
        ctype='text/html; charset=utf-8' if path=='/' else 'application/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8'
        self._send(200,p.read_bytes(),ctype)
    def do_POST(self):
        if urlsplit(self.path).path!='/api/scan':self.json(404,{'error':'Not found'});return
        # Localhost-only server and reject browser requests from foreign websites.
        origin=self.headers.get('Origin','')
        if origin and urlsplit(origin).hostname not in ('127.0.0.1','localhost'):
            self.json(403,{'error':'Origin denied'});return
        try:
            length=int(self.headers.get('Content-Length','-1'))
        except ValueError:length=-1
        if length<1 or length>MAX_UPLOAD+1024*1024:
            self.json(413,{'error':'Upload too large (max 120 MB APK)'});return
        ctype=self.headers.get('Content-Type','')
        if 'multipart/form-data' not in ctype or 'boundary=' not in ctype:
            self.json(400,{'error':'Expected multipart/form-data'});return
        data=self.rfile.read(length)
        try:
            wrapper=('Content-Type: '+ctype+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+data
            message=BytesParser(policy=default).parsebytes(wrapper)
            if not message.is_multipart():raise ValueError('Invalid multipart upload')
            parts=[part for part in message.iter_parts() if part.get_param('name',header='content-disposition')=='file']
            if len(parts)!=1:raise ValueError('One APK file is required')
            part=parts[0]
            filename=os.path.basename(part.get_filename() or 'uploaded.apk')
            if not filename.lower().endswith('.apk'):raise ValueError('Only .apk files are accepted')
            payload=part.get_payload(decode=True)
            if payload is None or len(payload)>MAX_UPLOAD:raise ValueError('Invalid or oversized payload')
            report=deep_analyze(payload,filename)
            self.json(200,report)
        except (APKError,ValueError,KeyError) as e:
            self.json(422,{'error':str(e)})
        except Exception as e:
            print('[SPECTRA] analysis error:',repr(e),file=sys.stderr)
            self.json(500,{'error':'Internal analysis error. See terminal for details.'})

def main():
    p=argparse.ArgumentParser(description='SPECTRA local APK static analyzer')
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--no-browser',action='store_true')
    args=p.parse_args()
    # Hard bind to loopback; no LAN exposure.
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'\nSPECTRA Deep APK Analyzer\nOpen http://127.0.0.1:{args.port}\nOffline static analysis only. CTRL+C to stop.\n',flush=True)
    if not args.no_browser: threading.Timer(0.7,lambda:webbrowser.open(f'http://127.0.0.1:{args.port}')).start()
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
