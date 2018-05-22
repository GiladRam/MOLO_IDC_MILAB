import signal
import pytz
from scapy import config
import json
config.Conf.load_layers.remove("x509")
from scapy.all import *
from netaddr import *
from datetime import datetime
from expiringdict import ExpiringDict
import ssl
import paho.mqtt.client as mqtt

version = "0.3"

minute_list = []
list = []
MAX_LENGTH = 20
DEVICE_ID = 'Molo_1'
macAddressCache = ExpiringDict(max_len=100, max_age_seconds=120)
TIME_ZONE = 'Asia/Jerusalem'
os.environ['TZ'] = TIME_ZONE
time.tzset()
# Default interface config
interface = "wlan1mon"
# aws configurations
IoT_protocol_name = "x-amzn-mqtt-ca"
aws_iot_endpoint = "**********.iot.eu-west-1.amazonaws.com"
# mqtt parms
MQTT_TOPIC = "MOLO_1_Probe"
# cert
ca = "/root/MOLO/cert/root-CA.crt"
cert = "/root/MOLO/cert/MOLO_1.cert.pem"
private = "/root/MOLO/cert/MOLO_1.private.key"
fingerFormat = '{timestamp:%s, MAC:%s,SSID:%s, Quality:%s, OUI:%s, Signal Strength:%s}'


reload(sys)
sys.setdefaultencoding('utf-8')


def get_oui(pkt):
    global oui
    try:
        oui = OUI(pkt.addr2.replace(":","").upper()[0:6])
        oui = oui.registration().org
    except:
        oui = "(Unknown)"
    return oui


def handle_info(pkt):
    global finger_printDoc
    mac = pkt.addr2
    ssid = pkt.info.ljust(MAX_LENGTH)
    oui = get_oui(pkt)
    quality = get_signal_quality(pkt)
    time_stamp = datetime.now(pytz.timezone(TIME_ZONE)).strftime('%Y-%m-%dT%H:%M:%SZ')
    finger_printDoc = {}
    finger_printDoc['Device_id'] = DEVICE_ID
    finger_printDoc['Mac'] = mac
    finger_printDoc['OUI'] = oui
    finger_printDoc['Quality'] = quality
    finger_printDoc['Timestamp'] = time_stamp

    if macAddressCache.get(mac) is None:
        if quality > 30:
            print finger_printDoc
            macAddressCache[mac] = finger_printDoc
            mqtt_publish(finger_printDoc)


def mqtt_publish(finger_print):
    mqttc.loop_start()
    mqttc.publish(MQTT_TOPIC, json.dumps(finger_print))
    time.sleep(3)
    mqttc.loop_stop()


def get_signal_quality(pkt):
    db = -(256 - ord(pkt.notdecoded[-4:-3]))
    if db <= -100:
        raw_quality = 0
    elif db >= -50:
        raw_quality = 100
    else:
        raw_quality = 2 * (db + 100)
    return raw_quality


def packet_handler(pkt) :
    if pkt.haslayer(Dot11ProbeReq) :
        get_oui(pkt)
        handle_info(pkt)


def signal_handler(signal, frame):
    print "\n\033[92m\033[1m[+]\033[0m Exiting...\n"
    sys.exit(0)


def set_mqtt_client():
    global mqttc
    mqttc = mqtt.Client()

    ssl_context = ssl_alpn()
    mqttc.tls_set_context(context=ssl_context)
    print "start connect"
    mqttc.connect(aws_iot_endpoint, port=443)
    print "connect success"

def ssl_alpn():
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols([IoT_protocol_name])
        ssl_context.load_verify_locations(cafile=ca)
        ssl_context.load_cert_chain(certfile=cert, keyfile=private)
        return ssl_context
    except Exception as e:
        print("exception ssl_alpn()")
        raise e


set_mqtt_client()
signal.signal(signal.SIGINT, signal_handler)
sniff(iface=interface, prn=packet_handler, store=0)
signal.pause()
