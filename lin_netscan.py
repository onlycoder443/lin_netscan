import socket
import re
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import pyfiglet
import time
from tabulate import tabulate
from datetime import datetime
open_ports = []
lock = Lock()
def main():
    banner()
    try:
        host = input("Enter The IP/Domain(192.168.1.1/google.com):").strip().lower()
        start_r,end_r = input("Enter The Range[0-65535]:").split('-')
        start_r,end_r = int(start_r),int(end_r)
        if not 0 <= start_r <= 65535 and 0 <= end_r <= 65535:
                print("\033[91mInvalid Port Range\033[0m")
                return
        if  start_r > end_r:
                print("\033[91mError:\033[0m Start port must be less than or equal to End port.")
                return
        ip_port = input_checker(host,start_r,end_r)
        start_time = time.time()
        with ThreadPoolExecutor(max_workers = 1000) as executor:#change the max_workers based on your system performance
            executor.map(scanner,ip_port)
        end_time = time.time()
        if open_ports:
                data = []
                for port in sorted(open_ports):
                    data.append([port,"\033[92mOPEN\033[0m"])
                print(tabulate(data,headers =["Port","Status"],tablefmt = "grid"))
        else:
            print("\033[91mNo Open Port Found\033[0m")

        print(f"Scan Completed \033[92m100%\033[0m,Time Elapsed:\033[92m{end_time - start_time:.2f}\033[0mseconds")
    except ValueError:
        print("Enter Correct Range Value \033[91mSyntax:(0-65535)\033[0m")
    except KeyboardInterrupt:
        print("Exiting.......")

def banner():
    for i in range(3):
        print("\033[92m-\033[0m" * 80)
    print(pyfiglet.figlet_format("Lin.Net.Scan",font = 'cyberlarge'),end= '')
    print("\033[91m", datetime.now().strftime("%Y-%m-%d"), "\033[0m")
    for i in range(3):
        print("\033[92m-\033[0m" * 80)

def scanner(ipandport):
    host,port = ipandport
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)#set to 20-75 for proper response/complte TCP handshake
    result = s.connect_ex((host,port))
    s.close()
    if result == 0:
         with lock:
             open_ports.append(port)

def input_checker(host,start_r,end_r):
    if not re.search(r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$",host):
        try:
            host = socket.gethostbyname(host)
        except socket.gaierror:
            print("\033[92mInvalid Domain/IP Adress\033[0m")
            exit()

    ports = range(start_r,end_r+1)
    ip_port = ((host,port) for port in ports)
    return ip_port
if __name__ == "__main__":
     main()
