from requests import get
import json
import re
from time import sleep

apple_device_list = {
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
    if "MacBook" in m:
        return m
    if m.endswith("AP"):
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
