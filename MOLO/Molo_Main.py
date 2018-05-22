from wifi import Cell, Scheme
import subprocess as sp


# airmon-ng variables
AIRMON_NG = 'airmon-ng'
BASE_MON_INTERFACE = 'wlan1'
MON_INTERFACE = 'wlan1mon'
START_MONITOR_COMMAND = '%s start %s' %(AIRMON_NG, BASE_MON_INTERFACE)
STOP_MONITOR_COMMAND = '%s stop %s' %(AIRMON_NG, MON_INTERFACE)

# linux commands
IFCONFIG = 'ifconfig'

# Wifi AP dictionary
WIFI_DIC = {'GD':'****', 'IDC-Wireless':'***', 'MiLab':'****'}


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
        scheme = Scheme.for_cell('wlan0', cell.ssid, cell, WIFI_DIC[cell.ssid])
        scheme.activate()

import WhoIsHere
