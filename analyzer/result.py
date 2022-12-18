from analyzer.device import Device
from scapy.layers.l2 import Ether
from tabulate import tabulate

class Result:

    def __init__(self): 
        self.devices = dict() 

    def update(self, p):
        mac = p[Ether].src
        if mac not in self.devices:
            de = Device(p)
            if de.mac_address == "":
                return
            self.devices[mac] = de
        else:
            self.devices[mac].update(p)



    def csv(self):
        print("name,producer,model,ip_address,mac_address,packet_count,n_services")

        for s in self.devices.values():
            print("{},{},{},{},{},{}".format(s.probable_hostname, s.probable_producer, s.probable_model,s.ip_address, s.mac_address,s.packets,len(s.services)))

    def __str__(self):
        out = ""
        for v in self.devices.values():
            out += str(v)
            out += "\n"

        return out


    def table(self):
        headers = ["name","producer","model", "ip_address","mac_address","packet_count","n_services"]
        data = []
        for s in self.devices.values():
            data.append([s.probable_hostname, s.probable_producer, s.probable_model, s.ip_address, s.mac_address,s.packets,len(s.services)])

        print(tabulate(data, headers=headers))
