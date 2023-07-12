# Main modules
import argparse

print("""
      
      
                                     ______  _______  _______ 
                                    |  ____||__   __||__   __| 
                                    | |__      | |      | |   
                                    |  __|     | |      | |  
                                    | |        | |      | |  
                                    |_|        |_|      |_|    

 ______              _     _______                            __               _______                _
|  ____|            | |   |__   __|                          / _|             |__   __|              | |
| |__     __ _  ___ | |_     | |    _ __   __ _  _ __   ___ | |_   ___  _ __     | |     ___    ___  | |
|  __|   / _  |/ __|| __|    | |   |  __| / _  ||  _ \ / __||  _| / _ \|  __|    | |    / _ \  / _ \ | |
| |     | (_| |\__ \| |_     | |   | |   | (_| || | | |\__ \| |  |  __/| |       | |   | (_) || (_) || |
|_|      \__,_||___/ \__|    |_|   |_|    \__,_||_| |_||___/|_|   \___||_|       |_|    \___/  \___/ |_|

                                        Created By:
                                https://t.me/SidneyJobChannel
""")

def ftp_srv(
    dir: str = '/tmp',
    host: str = "0.0.0.0",
    port: int = 21,
    password: str = ''):
    
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    authorizer = DummyAuthorizer()
    
    if password:
        print(f'[*] FTP creds: user:{password}')
        authorizer.add_user('user', password, dir, perm="elradfmwMT")
        
    authorizer.add_anonymous(dir)
    
    handler = FTPHandler
    handler.authorizer = authorizer
    
    server = FTPServer((host, port), handler)
    
    print('[+] Starting FTP server')        
    server.serve_forever()
 
 
def base64_file(file: str) -> list:
    import base64
    import hashlib

    with open(file, 'rb') as f:
        f = f.read()
        print('[+] The file was successfully read')
    
    encoded = base64.b64encode(f).decode('UTF-8')
    hash = hashlib.md5(f).hexdigest()
    
    return [encoded, hash]
 
 
def upload_srv(
    port: int = 8000,
    bind: None = None,
    dir: str = '/tmp',
    token: None = None,
    theme: str = 'auto',
    server_certificate: None = None,
    client_certificate: None = None,
    basic_auth: None = None,
    basic_auth_upload: None = None,
    allow_replace: bool = False,
    cgi: bool = False):
    
    import uploadserver
    import os
    

    # Add creating folder

    uploadserver.main(
        port=port,
        bind=bind,
        dir=dir,
        token=token,
        theme=theme,
        server_certificate=server_certificate,
        client_certificate=client_certificate,
        basic_auth = basic_auth,
        basic_auth_upload = basic_auth_upload,
        allow_replace = allow_replace,
        cgi=cgi)
 
 
def WebDav_srv(
    dir: str = '/tmp',
    host: str = "0.0.0.0",
    port: int = 80):
    from cheroot import wsgi
    from wsgidav.wsgidav_app import WsgiDAVApp

    config = {
        "host": host,
        "port": port,
        "provider_mapping": {
            "/": dir,
        },
        "verbose": 1,
    }
    app = WsgiDAVApp(config)

    server_args = {
        "bind_addr": (config["host"], config["port"]),
        "wsgi_app": app,
    }
    
    server = wsgi.Server(**server_args)
    
    try:
        print('[+] Starting WebDav server')
        print(f'[*] Link for connecting to WebDav: \\\\ip\\DavWWWRoot')
        server.start()
    except KeyboardInterrupt:
        print(" [-] Received Ctrl-C: stopping…")
    finally:
        server.stop()

    
def simple_srv(
    dir: str = '/tmp',
    host: str = "0.0.0.0",
    port: int = 80):
    
    import http.server
    import os
    
    os.chdir(dir)
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

    print(f"[+] Start SimpleHTTPServer at port: {port}")
    httpd.serve_forever()
    

def encrypt(file: str, password: str):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import hashlib

    key_hash = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key_hash, AES.MODE_CBC)
    
    with open(file, 'rb') as file_:
        plaintext = file_.read()
    
    encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(file + '.enc', 'wb') as file_:
        file_.write(cipher.iv + encrypted)
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import hashlib

    key_hash = hashlib.sha256(password.encode()).digest()
    with open(file, 'rb') as file_:
        iv = file_.read(16)
        ciphertext = file_.read()
        

    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
        
        # Расшифровываем данные и записываем результат в новый файл
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(f'{file[:-4]}.dec', 'wb') as file_:
        file_.write(decrypted)
        
    print(f"[+] File {file} was successfully decrypted")
    print(f"[+] Path to the decrypted file [{file[:-4]}.dec] ")