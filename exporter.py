from prometheus_client.core import GaugeMetricFamily, REGISTRY
from prometheus_client import start_http_server, PROCESS_COLLECTOR, GC_COLLECTOR, PLATFORM_COLLECTOR
import time
import base64
import json
import logging
import urllib3
import os
from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5
from http import HTTPStatus

BUDERUS_ENDPOINTS = [  '/system/sensors/temperatures/outdoor_t1', \
                        '/system/sensors/temperatures/hotWater_t2', \
                        '/system/healthStatus', \
                        '/heatSources/actualPower' ,\
                        '/system/appliance/actualSupplyTemperature', \
                        '/heatSources/actualModulation', \
                        '/heatSources/workingTime/totalSystem' ,\
                        '/heatSources/systemPressure', \
                        '/heatSources/flameStatus', \
                        '/heatSources/ChimneySweeper', \
                        '/heatSources/numberOfStarts', \
                        '/notifications' 
                     ]
BUDERUS_MAGIC_BYTES = '867845e97c4e29dce522b9a7d3a3e07b152bffadddbed7f5ffd842e9895ad1e4'

results = []

buderus_host=os.getenv('buderus_host')
if(buderus_host is None):
    print("buderus_host not set. Can not continue...")
    exit(255)

buderus_access_token=os.getenv('buderus_access_token')
if(buderus_access_token is None):
    print("buderus_access_token not set. Can not continue...")
    exit(255)
buderus_access_token = buderus_access_token.replace('-', '')

buderus_password=os.getenv('buderus_password')
if(buderus_password is None):
    print("buderus_password not set. Can not continue...")
    exit(255)

exporter_port=os.getenv('exporter_port')
if(exporter_port is None):
    exporter_port = 9142

loglevel=os.getenv('loglevel')
if(loglevel is None):
    loglevel = "DEBUG"

class BuderusCollector(object):

    def __init__(self, buderus_host, buderus_access_token, buderus_password):
        self.km200_host = buderus_host
        self.cipher = AES.new(self.create_decryption_key(buderus_access_token, buderus_password), AES.MODE_ECB)
        self.pool_manager = urllib3.PoolManager()

    def collect(self):
        print ("Started collecting...")
        start = time.time()
        
        g_temperature = GaugeMetricFamily("buderus_temperatures_c", 'Buderus temperature metrics in °C', labels=['sensor'])
        g_power = GaugeMetricFamily("buderus_powers_kW", 'Buderus Power metrics in kW', labels=['sensor'])
        g_percent =  GaugeMetricFamily("buderus_percentages", 'Buderus metrics in %', labels=['sensor'])
        g_pressure =  GaugeMetricFamily("buderus_pressures_bar", 'Buderus pressure metrics in bar', labels=['sensor'])
        g_min = GaugeMetricFamily("buderus_minutes", 'Buderus metrics in minutes', labels=['sensor'])
        g_info =  GaugeMetricFamily("buderus_infos", 'Buderus informations', labels=['sensor','info'])
        g_number = GaugeMetricFamily("buderus_numbers", "Buderus numbers without unit", labels=['sensor'])
        g_state = GaugeMetricFamily("buderus_states", 'Buderus state metrics', labels=['sensor'])

        for api in BUDERUS_ENDPOINTS:
            self.query(f'http://{self.km200_host}{api}')
            for r in results:
                if r['type']=="C":                
                   g_temperature.add_metric([r['metric']], r['value'])

                elif r['type']=="kW":
                    g_power.add_metric([r['metric']], r['value'])

                elif r['type']=="%":
                    g_percent.add_metric([r['metric']], r['value'])

                elif r['type']=="bar":
                    g_pressure.add_metric([r['metric']], r['value'])

                elif r['type']=="info":
                    g_info.add_metric([r['metric'],r['value']],1)

                elif r['type']=="state":
                    g_state.add_metric([r['metric']], r['value'])

                elif r['type']=="mins":
                    g_min.add_metric([r['metric']], r['value'])

                elif r['type'].strip()=="":
                    g_number.add_metric([r['metric']], r['value'])

                else:
                    print(r)

            results.clear()

        yield g_temperature
        yield g_power
        yield g_percent
        yield g_pressure
        yield g_info
        yield g_state
        yield g_min
        yield g_number

        end = time.time()
        print(f"Collecting finished in {end-start} seconds")

    def log_message(self, format, *args):
        return

    def log_request(self, *args):
        return

    def create_decryption_key(self, gateway_password, private_password):
        part1 = MD5.new()
        part1.update(gateway_password.replace('-', '').encode() + bytes.fromhex(BUDERUS_MAGIC_BYTES))

        part2 = MD5.new()
        part2.update(bytes.fromhex(BUDERUS_MAGIC_BYTES) + private_password.encode())
	    
        logging.debug(part1.digest()[:32] + part2.digest()[:32])

        return part1.digest()[:32] + part2.digest()[:32]


    def decrypt_response_data(self, data):
        decoded = base64.b64decode(data)
        decrypted_bytes = self.cipher.decrypt(decoded)
        logging.debug(decrypted_bytes)

        plaintext = decrypted_bytes.decode('UTF-8').replace('\0', '')
        return json.loads(plaintext)

    def query(self, uri):
        try:
            response = self.pool_manager.request('GET', uri, headers={'User-Agent': 'TeleHeater', 'Content-type': 'application/json; charset=utf-8'})

            if response.status == HTTPStatus.OK:
                response_json = self.decrypt_response_data(response.data)
                if response_json['type'] == 'refEnum':
                    for reference in response_json['references']:
                        result = self.query(reference['uri'])
                    return 
                else:
                    result = self.get_prometheus_metric(response_json)
                    if result:
                        results.append(result)
                    return result

            else:
                logging.warning(f"'{uri}' request was not successful: {response.status} {HTTPStatus(response.status).phrase}")

        except Exception:
            logging.exception(f"'{uri}' error while processing")

    def get_prometheus_metric(self, json):
        metric_name = f"{json['id'].replace('/','_')}"

        if json['type'] == 'stringValue':

            if json['value'] in ["off", "on", "false", "true", "INACTIVE", "ACTIVE", "stop", "start", "error", "ok"]:
    
                return dict (type = "state",
                            metric = metric_name,
                            value = 1.0 if json['value'].lower() in ['on', 'true', 'active', 'start', 'ok'] else 0.0
                )
               
            else:

                return dict (type = "info",
                            metric = metric_name,
                            value= json['value'],
                )

        elif json['type'] == 'floatValue':
 
                return dict (type = json['unitOfMeasure'], 
                            metric = metric_name,
                            value = json['value']
                )
        elif json['type'] == 'errorList':
 
                return dict (type = "state", 
                            metric = metric_name,
                            value = len(json['values'])
                )
        else:
            logging.warning(f"Unhandled data type: {json}")



if __name__ == '__main__':
    logging.basicConfig(level=loglevel)

    print(f'Exporter starting at port {exporter_port}')

    start_http_server(int(exporter_port))
    REGISTRY.unregister(PROCESS_COLLECTOR)
    REGISTRY.unregister(PLATFORM_COLLECTOR)
    REGISTRY.unregister(GC_COLLECTOR)
    REGISTRY.register(BuderusCollector(buderus_host, buderus_access_token, buderus_password))    
 
    while True:
        time.sleep(1)
 