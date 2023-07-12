import http.server, http, cgi, pathlib, sys, argparse, ssl, os, builtins
import tempfile, base64, binascii

# Does not seem to do be used, but leaving this import out causes uploadserver to not receive IPv4 requests when
# started with default options under Windows
import socket 

if sys.version_info.major > 3 or sys.version_info.minor >= 7:
    import functools

if sys.version_info.major > 3 or sys.version_info.minor >= 8:
    import contextlib

CSS = {
    'light': '',
    'auto': '''<style type="text/css">
@media (prefers-color-scheme: dark) {
  body {
    background-color: #000;
    color: #fff;
  }
}
</style>''',
    'dark': '''<style type="text/css">
body {
  background-color: #000;
  color: #fff;
}
</style>'''
}

def get_upload_page(theme):
    return bytes('''<!DOCTYPE html>
<html>
<head>
<title>File Upload</title>
<meta name="viewport" content="width=device-width, user-scalable=no" />''' \
    + CSS.get(theme) + '''
</head>
<body>
<h1>File Upload</h1>
<form action="upload" method="POST" enctype="multipart/form-data">
<input name="files" type="file" multiple />
<br />
<br />
Token (only needed if server was started with token option): <input name="token" type="text" />
<br />
<br />
<input type="submit" />
</form>
<p id="deprecation-notice"></p>
<p id="task"></p>
<p id="status"></p>
</body>
<script>
document.getElementsByName('token')[0].value=localStorage.token || ''

document.getElementsByTagName('form')[0].addEventListener('submit', async e => {
  e.preventDefault()
  
  if(e.target.token.value) {
    document.getElementById('deprecation-notice').textContent = 'NOTICE: Token will be deprecated in a future release, please configure the server to use the new HTTP basic auth options instead'
  }
  
  localStorage.token = e.target.token.value
  
  const tokenValidationFormData = new FormData()
  tokenValidationFormData.append('token', e.target.token.value)
  
  let tokenValidationResponse;
  try {
    tokenValidationResponse = await fetch('/upload/validateToken', { method: 'POST', body: tokenValidationFormData})
  } catch (e) {
    tokenValidationResponse = {
      ok: false,
      status: "Token validation unsuccessful",
      statusText: e.message,
    }
  }
  
  if (!tokenValidationResponse.ok) {
    let message = `${tokenValidationResponse.status}: ${tokenValidationResponse.statusText}`
    document.getElementById('status').textContent = message
    console.log(tokenValidationResponse)
    return
  }
  message = `Success: ${tokenValidationResponse.statusText}`
  const uploadFormData = new FormData(e.target)
  const filenames = uploadFormData.getAll('files').map(v => v.name).join(', ')
  const uploadRequest = new XMLHttpRequest()
  uploadRequest.open(e.target.method, e.target.action)
  uploadRequest.timeout = 3600000
  
  uploadRequest.onreadystatechange = () => {
    if (uploadRequest.readyState === XMLHttpRequest.DONE) {
      let message = `${uploadRequest.status}: ${uploadRequest.statusText}`
      if (uploadRequest.status === 204) message = `Success: ${uploadRequest.statusText}`
      if (uploadRequest.status === 0) message = 'Connection failed'
      document.getElementById('status').textContent = message
    }
  }
  
  uploadRequest.upload.onprogress = e => {
    let message = e.loaded === e.total ? 'Saving…' : `${Math.floor(100*e.loaded/e.total)}% [${e.loaded >> 10} / ${e.total >> 10}KiB]`
    document.getElementById("status").textContent = message
  }
  
  uploadRequest.send(uploadFormData)
  
  document.getElementById('task').textContent = `Uploading ${filenames}:`
  document.getElementById('status').textContent = '0%'
})
</script>
</html>''', 'utf-8')

def send_upload_page(handler):
    handler.send_response(http.HTTPStatus.OK)
    handler.send_header('Content-Type', 'text/html; charset=utf-8')
    handler.send_header('Content-Length', len(get_upload_page(args["theme"])))
    handler.end_headers()
    handler.wfile.write(get_upload_page(args["theme"]))

class PersistentFieldStorage(cgi.FieldStorage):
    # Override cgi.FieldStorage.make_file() method. Valid for Python 3.1 ~ 3.10. Modified version of the original
    # .make_file() method (base copied from Python 3.10)
    def make_file(self):
        if self._binary_file:
            return tempfile.NamedTemporaryFile(mode = 'wb+', dir = args["dir"], delete = False)
        else:
            return tempfile.NamedTemporaryFile("w+", dir = args["dir"], delete = False,
                encoding = self.encoding, newline = '\n')

def auto_rename(path):
    if not os.path.exists(path):
        return path
    (base, ext) = os.path.splitext(path)
    for i in range(1, sys.maxsize):
        renamed_path = f'{base} ({i}){ext}'
        if not os.path.exists(renamed_path):
            return renamed_path
    raise FileExistsError(f'File {path} already exists.')

def validate_token(handler):
    form = PersistentFieldStorage(fp=handler.rfile, headers=handler.headers, environ={'REQUEST_METHOD': 'POST'})
    if args["token"]:
        # server started with token.
        if 'token' not in form or form['token'].value != args["token"]:
            # no token or token error
            handler.log_message('Token rejected (bad token)')
            return (http.HTTPStatus.FORBIDDEN, 'Token is enabled on this server, and your token is missing or wrong')
        return (http.HTTPStatus.NO_CONTENT, 'Token validation successful (good token)')
    return (http.HTTPStatus.NO_CONTENT, 'Token validation successful (no token required)')

def receive_upload(handler):
    result = (http.HTTPStatus.INTERNAL_SERVER_ERROR, 'Server error')
    name_conflict = False
    
    form = PersistentFieldStorage(fp=handler.rfile, headers=handler.headers, environ={'REQUEST_METHOD': 'POST'})
    if 'files' not in form:
        return (http.HTTPStatus.BAD_REQUEST, 'Field "files" not found')
    
    fields = form['files']
    if not isinstance(fields, list):
        fields = [fields]
    
    if not all(field.file and field.filename for field in fields):
        return (http.HTTPStatus.BAD_REQUEST, 'No files selected')
    
    for field in fields:
        if field.file and field.filename:
            filename = pathlib.Path(field.filename).name
        else:
            filename = None
        
        if args["token"]:
            # server started with token.
            if 'token' not in form or form['token'].value != args["token"]:
                # no token or token error
                handler.log_message('Upload of "{}" rejected (bad token)'.format(filename))
                result = (http.HTTPStatus.FORBIDDEN, 'Token is enabled on this server, and your token is missing or wrong')
                continue # continue so if a multiple file upload is rejected, each file will be logged
        
        if filename:
            destination = pathlib.Path(args["dir"]) / filename
            if os.path.exists(destination):
                if args["allow_replace"] and os.path.isfile(destination):
                    os.remove(destination)
                else:
                    destination = auto_rename(destination)
                    name_conflict = True
            if hasattr(field.file, 'name'):
                source = field.file.name
                field.file.close()
                os.rename(source, destination)
            else:  # class '_io.BytesIO', small file (< 1000B, in cgi.py), in-memory buffer.
                with open(destination, 'wb') as f:
                    f.write(field.file.read())
            handler.log_message(f'[Uploaded] "{filename}" --> {destination}')
            result = (http.HTTPStatus.NO_CONTENT, 'Some filename(s) changed due to name conflict' if name_conflict else 'Files accepted')
    
    return result

def check_http_authentication_header(handler, auth):
    auth_header = handler.headers.get('Authorization')
    if auth_header is None:
        return (False, 'No credentials given')
    
    auth_header_words = auth_header.split(' ')
    if len(auth_header_words) != 2:
        return (False, 'Credentials incorrectly formatted')
    
    if auth_header_words[0].lower() != 'basic':
        return (False, 'Credentials incorrectly formatted')
    
    try:
        http_username_password = base64.b64decode(auth_header_words[1]).decode()
    except binascii.Error:
        return (False, 'Credentials incorrectly formatted')
    
    http_username, http_password = http_username_password.split(':', 2)
    args_username, args_password = auth.split(':', 2)
    if http_username != args_username: return (False, 'Bad username')
    if http_password != args_password: return (False, 'Bad password')
    
    return (True, None)

def check_http_authentication(handler):
    """
        This function should be called in at the beginning of HTTP method handler.
        It validates Authorization header and sends back 401 response on failure.
        It returns False if this happens.
    """
    if handler.path in ['/upload', '/upload/validateToken']:
        auth = args["basic_auth"] or args["basic_auth_upload"]
    else:
        auth = args["basic_auth"]
    
    # If no auth settings apply, check always passes
    if not auth: return True
    
    valid, message = check_http_authentication_header(handler, auth)
    
    if not valid:
        handler.log_message(f'Request rejected ({message})')
        handler.send_response(http.HTTPStatus.UNAUTHORIZED, message)
        handler.send_header('WWW-Authenticate', 'Basic realm="uploadserver"')
        handler.end_headers()
    
    return valid

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if not check_http_authentication(self): return
        
        if self.path == '/upload':
            send_upload_page(self)
        else:
            super().do_GET()
    
    def do_POST(self):
        if not check_http_authentication(self): return
        
        if self.path in ['/upload', '/upload/validateToken']:
            if self.path == '/upload/validateToken':
                result = validate_token(self)
            elif self.path == '/upload':
                result = receive_upload(self)
            if result[0] < http.HTTPStatus.BAD_REQUEST:
                self.send_response(result[0], result[1])
                self.end_headers()
            else:
                self.send_error(result[0], result[1])
        else:
            self.send_error(http.HTTPStatus.NOT_FOUND, 'Can only POST/PUT to /upload')
    
    def do_PUT(self):
        self.do_POST()

class CGIHTTPRequestHandler(http.server.CGIHTTPRequestHandler):
    def do_GET(self):
        if not check_http_authentication(self): return
        
        if self.path == '/upload':
            send_upload_page(self)
        else:
            super().do_GET()
    
    def do_POST(self):
        if not check_http_authentication(self): return
        
        if self.path in ['/upload', '/upload/validateToken']:
            if self.path == '/upload/validateToken':
                result = validate_token(self)
            elif self.path == '/upload':
                result = receive_upload(self)
            if result[0] < http.HTTPStatus.BAD_REQUEST:
                self.send_response(result[0], result[1])
                self.end_headers()
            else:
                self.send_error(result[0], result[1])
        else:
            super().do_POST()
    
    def do_PUT(self):
        self.do_POST()

def intercept_first_print():
    if args["server_certificate"]:
        # Use the right protocol in the first print call in case of HTTPS
        old_print = builtins.print
        def new_print(*args, **kwargs):
            old_print(args[0].replace('HTTP', 'HTTPS').replace('http', 'https'), **kwargs)
            builtins.print = old_print
        builtins.print = new_print

def ssl_wrap(socket):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_root = pathlib.Path(args["dir"]).resolve()
    
    # Server certificate handling
    server_certificate = pathlib.Path(args["server_certificate"]).resolve()
    
    if not server_certificate.is_file():
        print('Server certificate "{}" not found, exiting'.format(server_certificate))
        sys.exit(4)
    
    if server_root in server_certificate.parents:
        print('Server certificate "{}" is inside web server root "{}", exiting'.format(server_certificate, server_root))
        sys.exit(3)
    
    context.load_cert_chain(certfile=server_certificate)
    
    if args["client_certificate"]:
        # Client certificate handling
        client_certificate = pathlib.Path(args["client_certificate"]).resolve()
        
        if not client_certificate.is_file():
            print('Client certificate "{}" not found, exiting'.format(client_certificate))
            sys.exit(4)
        
        if server_root in client_certificate.parents:
            print('Client certificate "{}" is inside web server root "{}", exiting'.format(client_certificate, server_root))
            sys.exit(3)
    
        context.load_verify_locations(cafile=client_certificate)
        context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        return context.wrap_socket(socket, server_side=True)
    except ssl.SSLError as e:
        print('SSL error: "{}", exiting'.format(e))
        sys.exit(5)

def serve_forever():
    # Verify arguments in case the method was called directly
    
    if args["cgi"]:
        handler_class = CGIHTTPRequestHandler
    elif sys.version_info.major == 3 and sys.version_info.minor < 7:
        handler_class = SimpleHTTPRequestHandler
    else:
        handler_class = functools.partial(SimpleHTTPRequestHandler, directory=args["dir"])
    
    print(f'[+] File upload available at 127.0.0.1:{args["port"]}/upload')
    print(f'[INFO] Folder where files will be saved: {args["dir"]}')
    
    if sys.version_info.major == 3 and sys.version_info.minor < 8:
        # The only difference in http.server.test() between Python 3.6 and 3.7 is the default value of ServerClass
        if sys.version_info.minor < 7:
            from http.server import HTTPServer as DefaultHTTPServer
        else:
            from http.server import ThreadingHTTPServer as DefaultHTTPServer
        
        class CustomHTTPServer(DefaultHTTPServer):
            def server_bind(self):
                bind = super().server_bind()
                if args["server_certificate"]:
                    self.socket = ssl_wrap(self.socket)
                return bind
        server_class = CustomHTTPServer
    else:
        class DualStackServer(http.server.ThreadingHTTPServer):
            def server_bind(self):
                # suppress exception when protocol is IPv4
                with contextlib.suppress(Exception):
                    self.socket.setsockopt(
                        socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                bind = super().server_bind()
                if args["server_certificate"]:
                    self.socket = ssl_wrap(self.socket)
                return bind
        server_class = DualStackServer
    
    intercept_first_print()
    http.server.test(
        HandlerClass=handler_class,
        ServerClass=server_class,
        port=args["port"],
        bind=args["bind"],
    )

def main(
    port: int,
    bind: None,
    dir: str,
    token: None,
    theme: str,
    server_certificate: None,
    client_certificate: None,
    basic_auth: None,
    basic_auth_upload: None,
    allow_replace: bool,
    cgi: bool
):
    global args
    
    args = {}

    # Set vars
    args["port"] = port
    args["bind"] = bind
    args["dir"] = dir
    args["token"] = token
    args["theme"] = theme
    args["server_certificate"] = server_certificate
    args["client_certificate"] = client_certificate
    args["basic_auth"] = basic_auth
    args["basic_auth_upload"] = basic_auth_upload 
    args["allow_replace"] = allow_replace
    args["cgi"] = cgi

    serve_forever()
