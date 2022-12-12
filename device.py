from scapy.all import *

class Device:
    probable_hostname = ""
    mac_address = ""

    def __init__(self, p):
        self.update(p)
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
        if DNSQR not in d:
            return
        qr = d[DNSQR]
        if qr.qtype != 255:
            return
        
        if self.mac_address != p[Ether].src:
            return

        service_name = qr.qname.decode('utf8')
        if self.probable_hostname == "":
            self.probable_hostname = service_name


    def __str__(self):
        return "\nprobable hostname: " + self.probable_hostname + "\nmac address: " + self.mac_address + "\n\n"

    def __repr__(self):
        return "\nprobable hostname: " + self.probable_hostname + "\nmac address: " + self.mac_address + "\n\n"

