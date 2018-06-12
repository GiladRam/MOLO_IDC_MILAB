
# version = "0.4"

from scapy.all import *
from netaddr import *
from datetime import datetime
from scapy import config
from expiringdict import ExpiringDict
import sys
import hashlib
import signal
import pytz
import json
import time
import os
import ssl
import paho.mqtt.client as mqtt
import configparser

# Remove TSL layer
config.Conf.load_layers.remove("x509")
# Max ssid length
MAX_LENGTH = 20
# Create a cache for mac address duplications
macAddressCache = ExpiringDict(max_len=100, max_age_seconds=120)
fingerFormat = '{timestamp:%s, MAC:%s, SSID:%s, Quality:%s, OUI:%s, Signal Strength:%s}'
reload(sys)
sys.setdefaultencoding('utf-8')
# Configuration sectios
SECTION_DEVICE = 'Device'
SECTION_AWS = 'AWS'
SECTION_MQTT = 'MQTT'
SECTION_CERT = 'Cert'


known_Wifi = dict()


class WhoIsHere:

    def __init__(self):

        config_path = os.path.join("/root/MOLO/config", "config.ini")
        config_file = configparser.ConfigParser()
        config_file.read(config_path)

        self.device_id = config_file[SECTION_DEVICE]['ID']
        self.time_zone = config_file[SECTION_DEVICE]['TIME_ZONE']
        os.environ['TZ'] = self.time_zone
        time.tzset()
        # Default interface config
        self.interface = config_file[SECTION_DEVICE]['INTERFACE']
        # aws configurations
        self.iot_protocol_name = config_file[SECTION_AWS]['IoT_protocol_name']
        self.aws_iot_endpoint = config_file[SECTION_AWS]['aws_iot_endpoint']
        # MQTT parms
        self.mqtt_topic =config_file[SECTION_MQTT]['MQTT_TOPIC']
        # cert
        self.path_to_ca_file = config_file[SECTION_CERT]['ca']
        self.path_to_cert_file = config_file[SECTION_CERT]['cert']
        self.path_to_private_key = config_file[SECTION_CERT]['private']

    @staticmethod
    def get_oui(pkt):
        global oui
        try:
            oui = OUI(pkt.addr2.replace(":","").upper()[0:6])
            oui = oui.registration().org
        except:
            oui = "(Unknown)"
        return oui

    def handle_info(self, pkt):
        global finger_printDoc
        mac = pkt.addr2
        ssid = pkt.info.ljust(MAX_LENGTH)
        oui = self.get_oui(pkt)
        quality = self.get_signal_quality(pkt)
        time_stamp = datetime.now(pytz.timezone(self.time_zone)).strftime('%Y-%m-%dT%H:%M:%SZ')
        finger_printDoc = {}
        finger_printDoc['Device_id'] = self.device_id
        finger_printDoc['Mac'] = hashlib.md5(mac).hexdigest()
        finger_printDoc['OUI'] = oui
        finger_printDoc['Quality'] = quality
        finger_printDoc['Timestamp'] = time_stamp

        if macAddressCache.get(mac) is None:
            if quality > 30:
                print finger_printDoc
                macAddressCache[mac] = finger_printDoc
                self.mqtt_publish(finger_printDoc)

    def mqtt_publish(self, finger_print):
        mqttc.loop_start()
        mqttc.publish(self.mqtt_topic, json.dumps(finger_print))
        time.sleep(3)
        mqttc.loop_stop()

    @staticmethod
    def get_signal_quality(pkt):
        db = -(256 - ord(pkt.notdecoded[-4:-3]))
        if db <= -100:
            raw_quality = 0
        elif db >= -50:
            raw_quality = 100
        else:
            raw_quality = 2 * (db + 100)
        return raw_quality


    def packet_handler(self, pkt) :
        if pkt.haslayer(Dot11ProbeReq):
            self.get_oui(pkt)
            self.handle_info(pkt)

    @staticmethod
    def signal_handler(signal, frame):
        print "\n\033[92m\033[1m[+]\033[0m Exiting...\n"
        sys.exit(0)

    def set_mqtt_client(self):
        global mqttc
        mqttc = mqtt.Client()

        ssl_context = self.ssl_alpn()
        mqttc.tls_set_context(context=ssl_context)
        print "start connect"
        mqttc.connect(self.aws_iot_endpoint, port=443)
        print "connect success"

    def ssl_alpn(self):
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.set_alpn_protocols([self.iot_protocol_name])
            ssl_context.load_verify_locations(cafile=self.path_to_ca_file)
            ssl_context.load_cert_chain(certfile=self.path_to_cert_file, keyfile=self.path_to_private_key)
            return ssl_context
        except Exception as e:
            print("exception ssl_alpn()")
            raise e


    def run(self):
        self.set_mqtt_client()
        signal.signal(signal.SIGINT, self.signal_handler)
        sniff(iface=str(self.interface), prn=self.packet_handler, store=0)
        signal.pause()


if __name__ == '__main__':
    find = WhoIsHere()
    find.run()