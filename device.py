from scapy.all import *

class Device:



    def __init__(self, p):
        self.probable_hostname = ""
        self.mac_address = ""
        self.packets = 1
        self.services = dict()
        if Ether not in p:
            return
        if DNS not in p[Ether]:
            return
        d = p[DNS]
        if DNSQR not in d:
            return
        qr = d[DNSQR]
        if qr.qtype != 255:
            return
        
        self.mac_address = p[Ether].src
        service_name = qr.qname.decode('utf8')
        self.probable_hostname = service_name.split(".", 1)[0]


    def update(self, p):
        if Ether not in p:
            return
        if DNS not in p[Ether]:
            return
        d = p[DNS]
        # dns.count.queries == 1 && dns.count.answers == 0 && dns.count.auth_rr == 0 && dns.count.add_rr == 0
        if d.ancount == 0 and d.arcount == 0 and d.ancount == 0:
            service_name = d[DNSQR].qname
            if service_name not in self.services:
                self.services[service_name] = 1
            else:
                self.services[service_name] = self.services[service_name] + 1
        if DNSQR not in d:
            return
        qr = d[DNSQR]
        if qr.qtype != 255:
            return
        
        if self.mac_address != p[Ether].src:
            return

        service_name = qr.qname.decode('utf8')
        self.packets = self.packets + 1
        if self.probable_hostname == "":
            self.probable_hostname = service_name.split(".", 1)[0]






    def __str__(self):
        return "\nprobable hostname: " + self.probable_hostname + "\nmac address: " + self.mac_address + "\npackets: " + str(self.packets) + "\nservices: " + str(self.services) + "\n"

    def __repr__(self):
        return "\nprobable hostname: " + self.probable_hostname + "\nmac address: " + self.mac_address + "\npackets: " + str(self.packets) + "\nservices: " + str(self.services) + "\n"

