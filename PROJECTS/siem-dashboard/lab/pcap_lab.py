
import os, sys, socket
import json, threading, time
from pathlib import Path
for key in ("PYTHONPATH","PYTHONHOME","VIRTUAL_ENV"):
    os.environ.pop(key, None)
SIEM = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SIEM)
WORK = os.environ.get("SIEM_LAB_WORK") or str(Path(__file__).resolve().parent / "out")
os.makedirs(WORK, exist_ok=True)
LOG = os.path.join(WORK, "pcap_lab.log")
log = open(LOG, "w", encoding="utf-8", buffering=1)
def say(m):
    log.write(m + "\n")

from scapy.all import AsyncSniffer, wrpcap, conf
conf.use_pcap = True

captured = []
sniffer = AsyncSniffer(iface=r"\Device\NPF_Loopback", prn=lambda p: captured.append(p),
                       store=True, promisc=False)
sniffer.start()
time.sleep(1.0)
say("sniffing loopback")

def listener(port, backlog=4):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(backlog)
    return s

# a DNS responder that answers with a deliberately large TXT record
def dns_server(sock, txt, stop):
    while not stop.is_set():
        try:
            sock.settimeout(0.5)
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            continue
        except OSError:
            break
        # echo the query back with a TXT answer appended (a real UDP exchange on
        # the wire, which is what the importer reads)
        resp = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00" + data[12:]
        resp += b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(txt).to_bytes(2,"big") + b"\x00" + txt
        sock.sendto(resp, addr)

def dns_query(port, name):
    q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); q.settimeout(1.0)
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00\x00\x10\x00\x01"
    q.sendto(query, ("127.0.0.1", port))
    try: q.recvfrom(4096)
    except Exception: pass
    q.close()

stop = threading.Event()
udp53 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    udp53.bind(("127.0.0.1", 53))
    dns_ok = True
except OSError as exc:
    dns_ok = False
    say("port 53 unavailable: %s" % exc)
if dns_ok:
    threading.Thread(target=dns_server, args=(udp53, b"X"*220, stop), daemon=True).start()

markers = []
def window(label, action):
    started = time.time(); action(); ended = time.time()
    time.sleep(0.6)
    markers.append({"label": label, "started": started, "ended": ended})
    say("  %-14s %.2fs" % (label, ended-started))

# --- the techniques the network rules name --------------------------------
s23 = listener(23); s21 = listener(21); s25 = listener(25)
s8443 = listener(18443); s8080 = listener(18888)

def connect(port, payload=b""):
    c = socket.socket(); c.settimeout(2)
    try:
        c.connect(("127.0.0.1", port))
        if payload: c.sendall(payload)
        try: c.recv(64)
        except Exception: pass
    finally:
        c.close()

def accept(sock):
    try:
        sock.settimeout(0.5); conn, _ = sock.accept(); conn.close()
    except Exception: pass

# accept in the background so the connections complete
for s in (s23, s21, s25, s8443, s8080):
    threading.Thread(target=accept, args=(s,), daemon=True).start()

window("T1040",  lambda: (connect(23, b"login: admin\r\npassword: hunter2\r\n"), connect(21, b"USER admin\r\n")))
window("T1040b", lambda: connect(25, b"EHLO lab\r\n"))
if dns_ok:
    window("T1048.003", lambda: dns_query(53, "exfil.lab.test"))
window("benign", lambda: (connect(18443), connect(18888), connect(18888)))
if dns_ok:
    window("benign", lambda: dns_query(53, "www.example.test"))

stop.set(); time.sleep(1.5)
try: sniffer.stop()
except Exception: pass
time.sleep(0.5)
say("packets captured: %d" % len(captured))
out = os.path.join(WORK, "lab.pcap")
if captured:
    wrpcap(out, captured)
    say("wrote %s (%d bytes)" % (out, os.path.getsize(out)))
json.dump({"markers": markers, "dns": dns_ok}, open(os.path.join(WORK,"pcap_windows.json"),"w"), indent=1)
for s in (s23, s21, s25, s8443, s8080):
    s.close()
log.close()
