from wifi import Cell, Scheme
import subprocess as sp
from WhoIsHere import WhoIsHere
import configparser
import os

# airmon-ng variables
AIRMON_NG = 'airmon-ng'
BASE_MON_INTERFACE = 'wlan1'
MON_INTERFACE = 'wlan1mon'
START_MONITOR_COMMAND = '%s start %s' %(AIRMON_NG, BASE_MON_INTERFACE)
STOP_MONITOR_COMMAND = '%s stop %s' %(AIRMON_NG, MON_INTERFACE)

# linux commands
IFCONFIG = 'ifconfig'
REBOOT_COMMAND = "shutdown -r +600"

configPath = os.path.join("root/MOLO/config", "config.ini")
SECTION_KNOWN_WIFI = 'Known WIFI'

config = configparser.ConfigParser()
config.optionxform = str
config.read(configPath)
WIFI_DIC = dict()

def set_all_known_wifis():
    for wifi in config[SECTION_KNOWN_WIFI]:
        WIFI_DIC[str(wifi)] = config[SECTION_KNOWN_WIFI][wifi]
        if WIFI_DIC[str(wifi)] == '':
            WIFI_DIC[str(wifi)] = None


def main():
    output = sp.Popen([AIRMON_NG, 'start', BASE_MON_INTERFACE], stdout=sp.PIPE)
    stream = output.communicate()[0]
    print output.returncode
    output = sp.Popen(IFCONFIG, stdout=sp.PIPE)
    while True:
        line = output.stdout.readline()
        if line != '':
            print line.rstrip()
        else:
            break
    stream = output.communicate()[0]
    print output.returncode
    list_of_cells = Cell.all('wlan0')
    for cell in list_of_cells:
        if cell.ssid in WIFI_DIC:
            print 'in!!!'
            scheme = Scheme.for_cell('wlan0', cell.ssid, cell, WIFI_DIC[cell.ssid])
            try:
                scheme.save()
            except:
                print "saved scheme"
            scheme.activate()


if __name__ == '__main__':

    set_all_known_wifis()
    main()
    os.system(REBOOT_COMMAND)
    find = WhoIsHere.WhoIsHere()
    find.run()
