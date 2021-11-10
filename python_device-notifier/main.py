import nmap3
import json
import re
import os
import datetime
import ctypes
import sys


LOG_LOCATION = ""
EXCLUDED = []
NETWORK = ""
MAX_BYTES = 512
TIME = "0"


def getQuoted(line):
    return re.findall(r'"(.*?)"', line)


#burde brukt et json lib sikkert
def init():
    global LOG_LOCATION
    global NETWORK
    global EXCLUDED
    global MAX_BYTES

    for line in open("./device_notifier_config.ini", "r").readlines():
        if line.startswith("LOG_LOCATION"):
            line = getQuoted(line)[0]
            line = line.rstrip()
            LOG_LOCATION = line if line.endswith("/") else line + "/"

        elif line.startswith("NETWORK"):
            NETWORK = getQuoted(line)[0]

        elif line.startswith("EXCLUDED"):
            EXCLUDED = getQuoted(line)

        elif line.startswith("MAX_BYTES"):
            MAX_BYTES = getQuoted(line)[0]


def getDatetimeStr():
    return str(datetime.datetime.now()).split(".")[0]


# hvor masse plass tar alle filene(ikke folders) i logmappen?
def getSize():
   return sum(os.path.getsize(LOG_LOCATION + f) for f in os.listdir(LOG_LOCATION)if not os.path.isdir(LOG_LOCATION + f))


def save(mac_addr, log):
    with open(LOG_LOCATION + "device_" + mac_addr.replace(":","") + ".txt","a+") as f:
        f.write(log)


# MAYBE:
# også ha ini-defaults og ha optionale args for å override
def getScan(network):
    return json.loads(json.dumps(nmap3.NmapScanTechniques().nmap_ping_scan(network), indent=2))


def getDeviceData(results):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    profiles = []

    for scan_component in results:    
        
        if re.search(regex, scan_component):               
            ip_device = results[scan_component]
            device_profile = ""
            currentMac = "FF:FF:FF:FF"

            for key in ip_device:

                if not ip_device[key]:
                    continue
                elif any(ex in ip_device[key].values() for ex in EXCLUDED):
                    device_profile = ""
                    break 
                else:
                    if "addr" in ip_device[key]:
                        currentMac = ip_device[key]["addr"]
                    
                    device_profile += "\t - " + str(list(ip_device[key].values())) + "\n"
            
            if device_profile:
                profileStart = "\nIP: " + scan_component + "\nSCANNED AT: " + TIME
                device_profile = profileStart + "\n" + device_profile
                profiles.append((currentMac,device_profile))
               

    return profiles


def run():
    global TIME

    # conduct en NMAP-basert scan
    scanResults = getScan(NETWORK)

    # set den globale variabelen TIME
    TIME = getDatetimeStr()

    # extract data fra den og save.
    for p in getDeviceData(scanResults):
        save(p[0],p[1])

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    
    # note: windows sitt verifiserings-system(powershell rights osv) funker ikke alltid across windows-distros    
    #if is_admin():
        
    init()
    if not getSize() >= int(MAX_BYTES):
        print("AAAA")
        run()
    else:
        print("Error:. Too little bytes allowed by device_notifier_config.ini")

   # else:
        #print(os.path.realpath(__file__))
        
        # Re-run the program with admin rights
        #ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, os.path.realpath(__file__), None, 1)


    
if __name__=="__main__":
    main()
