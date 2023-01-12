from scapy.all import *
import socket

subnet = input("digitare rete e sottorete da scansionare: ") # Sottorete da scansionare
do_traceroute = input("vuoi effettuare traceroute per ogni indirizzo IP trovato? s/n: ") == "s"

def scan_network(subnet, do_traceroute):
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        try:
            hostname = gethostbyaddr(received.psrc)[0]
            if do_traceroute:
                traceroute = input("vuoi effettuare traceroute per l'indirizzo IP " + received.psrc + "? s/n: ") == "s"
                if traceroute:
                    result, unans = sr(IP(dst=received.psrc)/ICMP(), timeout=5, verbose=0, traceroute=True)
                    traceroute = [ hop.src for hop in result[0] ]
                else:
                    traceroute = []
            else:
                traceroute = []
                clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': hostname, 'traceroute': traceroute})
        except:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': "N/A", 'traceroute': []})
    return clients

network_hosts = scan_network(subnet, do_traceroute)

for host in network_hosts:
    print(host["ip"] + " - " + host["mac"] + " - " + host["hostname"] + " - " + str(host["traceroute"]))

host = input("Inserire l'indirizzo IP dell'host remoto da scansionare: ")

def scan_host(host):
    try:
        result, unans = sr(IP(dst=host)/ICMP(), timeout=5, verbose=0)
        if len(result) > 0:
            hostname = gethostbyaddr(host)[0]
            return {'ip': host, 'hostname': hostname, 'status': 'up'}
        else:
            return {'ip': host, 'hostname': "N/A", 'status': 'down'}
    except Exception as e:
        return {'ip': host, 'hostname': "N/A", 'status': 'error'}

remote_host = scan_host(host)
print(remote_host["ip"] + " - " + remote_host["hostname"] + " - " + remote_host["status"])
