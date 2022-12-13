import device
from scapy.layers.l2 import Ether

class Result:

    def __init__(self): 
        self.devices = dict() 

    def update(self, p):
        mac = p[Ether].src
        if mac not in self.devices:
            de = device.Device(p)
            if de.mac_address == "":
                return
            self.devices[mac] = de
        else:
            self.devices[mac].update(p)


    def __str__(self):
        out = ""
        for v in self.devices.values():
            out += str(v)

        return out

