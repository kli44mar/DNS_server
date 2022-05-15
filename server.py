import pickle
import socket
import time
from datetime import datetime

from scapy.layers.dns import DNS, DNSRR
host = '127.0.0.1'
port = 53

types = {1: "A", 2: "NS"}


def serv():
    ip = '8.8.8.8'
    caches = get_cache()
    inv_cache = get_inv_cache()
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(200)
                sock.bind(('127.0.0.1', port))
                sock.recvfrom(1024)
                sock.recvfrom(1024)
                data, client_adrr = sock.recvfrom(1024)
                name, ty = parse_request(data)
                caches, inv_cache = check_cache(caches)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
                    if (name, ty) in inv_cache:
                        d = DNS(data)
                        r = caches[(name, ty)]
                        response = DNS(
                                id=d.id, ancount=1, qr=1,
                                an=DNSRR(rrname=str(name), type=ty, rdata=str(r[0][0]), ttl=int(r[1][0])))
                        sock.sendto(bytes(response), client_adrr)
                    else:
                        dns.sendto(data, (ip, 53))
                        data, addr = dns.recvfrom(1024)
                        if data:
                            answer = DNS(data)
                            if answer.an:
                                r = parse_answer(answer, answer.an)
                                n = r['name']
                                t = r["type"]
                                caches[(n, t)] = (r['data'], (r['ttl'], r['time']))
                                inv_cache.append((n, t))
                            if answer.ns:
                                r = parse_answer(answer, answer.ns)
                                n = r['name']
                                t = r["type"]
                                caches[(n, t)] = (r['data'], (r['ttl'], r['time']))
                                inv_cache.append((n, t))
                            if answer.ar:
                                r = parse_answer(answer, answer.ar)
                                n = r['name']
                                t = r["type"]
                                caches[(n, t)] = (r['data'], (r['ttl'], r['time']))
                                inv_cache.append((n, t))
                        sock.sendto(data, client_adrr)

        except socket.timeout:
            break
        except:
            break
        finally:
            with open("cache.txt", 'wb') as f:
                pickle.dump(caches, f)
            with open("inv_cache.txt", 'wb') as f:
                pickle.dump(inv_cache, f)


def parse_request(data):
    request = DNS(data)
    name = request.qd.qname.decode()
    ty = types[request.qd.qtype]
    return name, ty


def parse_answer(answer, answ):
    r = []
    ans = answ
    for _ in range(answer.ancount):
        r.append(str(ans.rdata))
        ans = ans.payload
    result = {"name": answ.rrname.decode(),
              "type": types[answer.qd.qtype],
              "ttl": answ.ttl,
              "time": datetime.now()}
    if not r:
        result['data'] = ' '
    else:
        result['data'] = r

    return result


def get_cache():
    with open('cache.txt', 'rb') as file:
        try:
            cashes = pickle.load(file)
            return cashes
        except:
            return {}


def get_inv_cache():
    with open('inv_cache.txt', 'rb') as file:
        try:
            cashes = pickle.load(file)
            return cashes
        except:
            return []


def check_cache(caches):
    new_cache = {}
    new_inv_cache = []
    if caches:
        for k in caches:
            times = caches[k][1][1]
            ttl = caches[k][1][0]
            t = datetime.now()
            pr = (int(time.mktime(times.timetuple())) + ttl) - int(time.mktime(t.timetuple()))
            if pr > 0:
                new_cache[k] = caches[k]
                new_inv_cache.append(k)
    return new_cache, new_inv_cache


if __name__ == '__main__':
    serv()
