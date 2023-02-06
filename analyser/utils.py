from requests import get
import json
import re
from scapy.all import *
from time import sleep
import os

osx_code_list = {
    "22":"OS X 13.0 (Ventura)",
    "21":"OS X 12.0 (Monterey)",
    "20":"OS X 11.0 (Big Sur)",
    "19":"OS X 10.15 (Catalina)",
    "18":"OS X 10.14 (Mojave)",
    "17":"OS X 10.13 (High Sierra)",
    "16":"OS X 10.12 (Sierra)",
    "15":"OS X 10.11 (El Capitan)",
    "14":"OS X 10.10 (Yosemite)",
    "13":"OS X 10.9 (Mavericks)",
    "12":"OS X 10.8 (Mountain Lion)",
    "11":"Mac OS X 10.7 (Lion)",
    "10":"Mac OS X 10.6 (Snow Leopard)",
    "9":"Mac OS X 10.5 (Leopard)",
    "8":"Mac OS X 10.4 (Tiger)",
    "7":"Mac OS X 10.3 (Panther)",
    "6":"Mac OS X 10.2 (Jaguar)",
    "5":"Mac OS X 10.1 (Puma)",
    "4":"Mac OS X 10.0 (Cheetah)",
}

apple_device_list = {
    "MacBookPro17,1":"MacBook Pro (13-inch, M1, 2020)",
    "MacBookPro16,1":"MacBook Pro (16-inch, 2019)",
    "MacBookPro16,2":"MacBook Pro (13-inch, 2020)",
    "MacBookPro15,4":"MacBook Pro (13-inch, 2019, Two Thunderbolt 3 ports)",
    "MacBookPro15,3":"MacBook Pro (15-inch, 2019)",
    "MacBookPro15,2":"MacBook Pro (13-inch, 2018, Four Thunderbolt 3 ports)",
    "MacBookPro15,1":"MacBook Pro (15-inch, 2018)",
    "MacBookPro14,3":"MacBook Pro (15-inch, 2017)",
    "MacBookPro14,2":"MacBook Pro (13-inch, 2017, Four Thunderbolt 3 ports)",
    "MacBookPro14,1":"MacBook Pro (13-inch, 2017, Two Thunderbolt 3 ports)",
    "MacBookPro13,3":"MacBook Pro (15-inch, 2016)",
    "MacBookPro13,2":"MacBook Pro (13-inch, 2016, Four Thunderbolt 3 ports)",
    "MacBookPro13,1":"MacBook Pro (13-inch, 2016, Two Thunderbolt 3 ports)",
    "MacBookPro12,1":"MacBook Pro (Retina, 13-inch, Early 2015)",
    "MacBookPro11,4":"MacBook Pro (Retina, 15-inch, Mid 2015)",
    "MacBookPro11,3":"MacBook Pro (Retina, 15-inch, Late 2013) - rev 2",
    "MacBookPro11,2":"MacBook Pro (Retina, 15-inch, Late 2013)",
    "MacBookPro11,1":"MacBook Pro (Retina, 13-inch, Late 2013)",
    "MacBookPro10,2":"MacBook Pro (Retina, 13-inch, Early 2013)",
    "MacBookPro10,1":"MacBook Pro (Retina, 15-inch, Early 2013)",
    "MacBookPro9,2":"MacBook Pro (13-inch, Mid 2012)",
    "MacBookPro9,1":"MacBook Pro (15-inch, Mid 2012)",
    "MacBookPro8,3":"MacBook Pro (17-inch, Late 2011)",
    "MacBookPro8,2":"MacBook Pro (15-inch, Late 2011)",
    "MacBookPro8,1":"MacBook Pro (13-inch, Late 2011)",
    "MacBookPro7,1":"MacBook Pro (13-inch, Mid 2010)",
    "MacBookPro6,2":"MacBook Pro (15-inch, Mid 2010)",
    "MacBookPro6,1":"MacBook Pro (17-inch, Mid 2010)",
    "MacBookPro5,5":"MacBook Pro (13-inch, Mid 2009)",
    "MacBookPro5,3":"MacBook Pro (15-inch, Mid 2009)",
    "MacBookPro5,2":"MacBook Pro (17-inch, Mid 2009)",
    "MacBookPro5,1":"MacBook Pro (15-inch, Late 2008)",
    "MacBookPro4,1":"MacBook Pro (17-inch, Early 2008)",
    "MacBook10,1":"MacBook (Retina, 12-inch, 2017)",
    "MacBook9,1":"MacBook (Retina, 12-inch, Early 2016)",
    "MacBook8,1":"MacBook (Retina, 12-inch, Early 2015)",
    "MacBook7,1":"MacBook (13-inch, Mid 2010)",
    "MacBookAir10,1":"MacBook Air (M1, 2020)",
    "MacBookAir9,1":"MacBook Air (Retina, 13-inch, 2020)",
    "MacBookAir8,2":"MacBook Air (Retina, 13-inch, 2019)",
    "MacBookAir8,1":"MacBook Air (Retina, 13-inch, 2018)",
    "MacBookAir7,2":"MacBook Air (13-inch, 2017)",
    "MacBookAir7,1":"MacBook Air (11-inch, Early 2015)",
    "MacBookAir6,2":"MacBook Air (13-inch, Early 2014)",
    "MacBookAir6,1":"MacBook Air (11-inch, Early 2014)",
    "MacBookAir5,2":"MacBook Air (13-inch, Mid 2012)",
    "MacBookAir5,1":"MacBook Air (11-inch, Mid 2012)",
    "MacBookAir4,2":"MacBook Air (13-inch, Mid 2011)",
    "MacBookAir4,1":"MacBook Air (11-inch, Mid 2011)",
    "MacBookAir3,2":"MacBook Air (13-inch, Late 2010)",
    "MacBookAir3,1":"MacBook Air (11-inch, Late 2010)",
    "MacBookAir2,1":"MacBook Air (Mid 2009)",
    "D101AP":"iPhone 7",
    "D10AP":"iPhone 7",
    "D111AP":"iPhone 7 Plus",
    "D11AP":"iPhone 7 Plus",
    "D16AP":"iPhone 13 mini",
    "D17AP":"iPhone 13",
    "D201AAP":"iPhone 8",
    "D201AP":"iPhone 8",
    "D20AAP":"iPhone 8",
    "D20AP":"iPhone 8",
    "D211AAP":"iPhone 8 Plus",
    "D211AP":"iPhone 8 Plus",
    "D21AAP":"iPhone 8 Plus",
    "D21AP":"iPhone 8 Plus",
    "D221AP":"iPhone X",
    "D22AP":"iPhone X",
    "D27AP":"iPhone 14",
    "D28AP":"iPhone 14 Plus",
    "D321AP":"iPhone XS",
    "D331AP":"iPhone XS Max",
    "D331pAP":"iPhone XS Max",
    "D421AP":"iPhone 11 Pro",
    "D431AP":"iPhone 11 Pro Max",
    "D49AP":"iPhone SE (3rd generation)",
    "D52gAP":"iPhone 12 mini",
    "D53gAP":"iPhone 12",
    "D53pAP":"iPhone 12 Pro",
    "D54pAP":"iPhone 12 Pro Max",
    "D63AP":"iPhone 13 Pro",
    "D64AP":"iPhone 13 Pro Max",
    "D73AP":"iPhone 14 Pro",
    "D74AP":"iPhone 14 Pro Max",
    "D79AP":"iPhone SE (2nd generation)",
    "J120AP":"iPad Pro (12.9-inch) (2nd generation)",
    "J121AP":"iPad Pro (12.9-inch) (2nd generation)",
    "J127AP":"iPad Pro (9.7-inch)",
    "J128AP":"iPad Pro (9.7-inch)",
    "J171aAP":"iPad (8th generation)",
    "J171AP":"iPad (7th generation)",
    "J172aAP":"iPad (8th generation)",
    "J172AP":"iPad (7th generation)",
    "J181AP":"iPad (9th generation)",
    "J182AP":"iPad (9th generation)",
    "J1AP":"iPad (3rd generation)",
    "J207AP":"iPad Pro (10.5-inch)",
    "J208AP":"iPad Pro (10.5-inch)",
    "J210AP":"iPad mini (5th generation)",
    "J211AP":"iPad mini (5th generation)",
    "J217AP":"iPad Air (3rd generation)",
    "J2AAP":"iPad (3rd generation)",
    "J2AP":"iPad (3rd generation)",
    "J307AP":"iPad Air (4th generation)",
    "J308AP":"iPad Air (4th generation)",
    "J310AP":"iPad mini (6th generation)",
    "J311AP":"iPad mini (6th generation)",
    "J317AP":"iPad Pro (11-inch)",
    "J317xAP":"iPad Pro (11-inch)",
    "J318AP":"iPad Pro (11-inch)",
    "J318xAP":"iPad Pro (11-inch)",
    "J320AP":"iPad Pro (12.9-inch) (3rd generation)",
    "J320xAP":"iPad Pro (12.9-inch) (3rd generation)",
    "J321AP":"iPad Pro (12.9-inch) (3rd generation)",
    "J321xAP":"iPad Pro (12.9-inch) (3rd generation)",
    "J407AP":"iPad Air (5th generation)",
    "J408AP":"iPad Air (5th generation)",
    "J417AP":"iPad Pro (11-inch) (2nd generation)",
    "J418AP":"iPad Pro (11-inch) (2nd generation)",
    "J420AP":"iPad Pro (12.9-inch) (4th generation)",
    "J421AP":"iPad Pro (12.9-inch) (4th generation)",
    "J517AP":"iPad Pro (11-inch) (3rd generation)",
    "J517xAP":"iPad Pro (11-inch) (3rd generation)",
    "J518AP":"iPad Pro (11-inch) (3rd generation)",
    "J518xAP":"iPad Pro (11-inch) (3rd generation)",
    "J522AP":"iPad Pro (12.9-inch) (5th generation)",
    "J522xAP":"iPad Pro (12.9-inch) (5th generation)",
    "J523AP":"iPad Pro (12.9-inch) (5th generation)",
    "J523xAP":"iPad Pro (12.9-inch) (5th generation)",
    "J617AP":"iPad Pro 11",
    "J71AP":"iPad Air",
    "J71bAP":"iPad (6th generation)",
    "J71sAP71tAP":"iPad (5th generation)" ,
    "J72AP":"iPad Air",
    "J72bAP":"iPad (6th generation)",
    "J72sAP72tAP" : "iPad (5th generation)" ,
    "J73AP":"iPad Air",
    "J81AP":"iPad Air 2",
    "J82AP":"iPad Air 2",
    "J85AP":"iPad mini 2",
    "J85mAP":"iPad mini 3",
    "J86AP":"iPad mini 2",
    "J86mAP":"iPad mini 3",
    "J87AP":"iPad mini 2",
    "J87mAP":"iPad mini 3",
    "J96AP":"iPad mini 4",
    "J97AP":"iPad mini 4",
    "J98aAP":"iPad Pro (12.9-inch)",
    "J99aAP":"iPad Pro (12.9-inch)",
    "K48AP":"iPad",
    "K93AAP":"iPad 2",
    "K93AP":"iPad 2",
    "K94AP":"iPad 2",
    "K95AP":"iPad 2",
    "M68AP":"iPhone",
    "N102AP":"iPod touch (6th generation)",
    "N104AP":"iPhone 11",
    "N112AP":"iPod touch (7th generation)",
    "N18AP":"iPod touch (3rd generation)",
    "N41AP":"iPhone 5",
    "N42AP":"iPhone 5",
    "N45AP":"iPod touch",
    "N48AP":"iPhone 5c",
    "N49AP":"iPhone 5c",
    "N51AP":"iPhone 5s",
    "N53AP":"iPhone 5s",
    "N56AP":"iPhone 6 Plus",
    "N61AP":"iPhone 6",
    "N66AP66mAP":"iPhone 6s Plus",
    "N69AP69uAP":"iPhone SE (1st generation)"  ,
    "N71AP71mAP":"iPhone 6s" ,
    "N72AP":"iPod touch (2nd generation)",
    "N78aAP":"iPod touch (5th generation)",
    "N78AP":"iPod touch (5th generation)",
    "N81AP":"iPod touch (4th generation)",
    "N82AP":"iPhone 3G",
    "N841AP":"iPhone XR",
    "N88AP":"iPhone 3GS",
    "N90AP":"iPhone 4",
    "N90bAP":"iPhone 4",
    "N92AP":"iPhone 4",
    "N94AP":"iPhone 4S",
    "P101AP":"iPad (4th generation)",
    "P102AP":"iPad (4th generation)",
    "P103AP":"iPad (4th generation)",
    "P105AP":"iPad mini",
    "P106AP":"iPad mini",
    "P107AP":"iPad mini",
}

cache = dict()


def determine_model(m):
    if m.endswith("AP") or "MacBook" in m:
        return get_apple_model(m)
    return "unknown_"

def get_apple_model(model):
    if model in apple_device_list:
        return apple_device_list[model]

    if model in cache:
        return cache[model]

    url = 'https://www.theiphonewiki.com/wiki/' + model
    try:
        body = get(url)
    except:
        return "unknown_"

    id = re.search("[i|I][a-zA-Z]+\d+,\d+(-[A|B])?", body.text)
    if id is None:
        return "unknown_"
    id = id.group(0)
    if id not in apple_device_list:
        return id
    cache[model] = apple_device_list[id]
    return cache[model]


def analyse_airplay_record(device, r):
    if device.producer == "unknown":
        device.producer = "Apple"

    if '_.airplay._tcp.local' in device.services:
        device.services['_.airplay._tcp.local'] = device.services['_.airplay._tcp.local'] 
    else: 
        device.services['_.airplay._tcp.local'] = 1 

    if device.producer == "unknown":
        device.producer = "Apple"
    if r.type != 16:
        return

    if device.hostname == "unknown":
        device.hostname = remove_service_from_name(r.rrname.decode('utf8'))
     
    if device.model == "unknown":
        model = next(m for m in r.rdata if (lambda x : b'model=' in x)(m))
        if model != None:
            model = model.decode('utf8')
            model = re.sub("model=", "", model)
            device.model = determine_model(model)
        

def analyse_raop_record(device, r):
    if device.producer == "unknown":
        device.producer = "Apple"

    if '_.raop._tcp.local' in device.services:
        device.services['_.raop._tcp.local'] = device.services['_.raop._tcp.local'] 
    else: 
        device.services['_.raop._tcp.local'] = 1 

    if r.type != 16:
        return

    if device.producer == "unknown":
        device.producer = "Apple"

    if device.hostname == "unknown":
        name = r.rrname.decode('utf8')
        if "@" in name:
            name = name.split("@")[1]
        device.hostname = remove_service_from_name(name)

    if device.model == "unknown":
        model = next(m for m in r.rdata if (lambda x : b'am=' in x)(m))
        if model != None:
            model = model.decode('utf8')
            model = re.sub("model=", "", model)
            device.model = determine_model(model)

def analyse_mi_connect_record(device, r):
    if r.type != 16:
        return
    
    if '_.mi-connect._udp.local' in device.services:
        device.services['_.mi-connect._udp.local'] = device.services['_.mi-connect._udp.local'] 
    else: 
        device.services['_.mi-connect._udp.local'] = 1 

    if device.producer == "unknown":
        device.producer = "Xiaomi"

    if device.hostname == "unknown":
        name = next(n for n in r.rdata if (lambda x : b'name=' in x)(n))
        if name != None:
            name = name.decode('utf8')
            name = re.sub("name=", "", name)
            device.hostname = name

def analyse_device_info_record(device, r):
    if r.type != 16:
        return 

    if '_.device-info._tcp.local' in device.services:
        device.services['_.device-info._tcp.local'] = device.services['_.device-info._tcp.local'] 
    else: 
        device.services['_.device-info._tcp.local'] = 1 

    if device.producer == "unknown":
        device.producer = "Apple"

    if device.hostname == "unknown":
        device.hostname = remove_service_from_name(r.rrname.decode('utf8'))

    if device.model == "unknown":
        try:
            model = next(m for m in r.rdata if (lambda x : b'model=' in x)(m))
            if model != None:
                model = model.decode('utf8')
                model = re.sub("model=", "", model)
                device.model = determine_model(model)
        except:
            return

    if "MacBook" in device.hostname and device.operating_system == "unknown":
        try:
            osx = next(m for m in r.rdata if (lambda x : b'osxvers=' in x)(m))
            if osx != None:
                osx = osx.decode('utf8')
                osx = re.sub("osxvers=", "", osx)
                device.operating_system = osx_code_list[osx]
        except:
            return


def printer(res, args): 
    examples = res.packets
    while True:
        if res.packets != examples:
            examples = res.packets
            continue

        os.system('clear')
        res.table()
        print("")
        res.print_report()

        sleep(5)
        if res.packets >= args.count and args.count != 0:
            return

def remove_service_from_name(name):
    return re.sub("(\._[a-zA-Z\-]+\._(tcp|udp))?\.local\.", "", name)

class Recorder:
    def __init__(self, f, res):
        self.f = f
        self.res = res

    def analyze_and_record(self, p):
       self.res.update(p)
       wrpcap(self.f, p, append=True)

