import os
import threading
#from dotenv import dotenv_values
import rsa
import json
import time
import base64
import socket
import hashlib
import logging
from threading import Thread
from tb_device_mqtt import TBDeviceMqttClient, TBPublishInfo
from dotenv import dotenv_values
import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import cryptography.exceptions as crypto_exceptions  


# Cargamos las variables de entorno desde el archivo .env_vars
env_vars = dotenv_values('/usr/src/app/.env_vars')

# Accedemos a las variables de entorno cargadas
api_key = env_vars.get('secret_key')
token = env_vars.get('token')
broker = env_vars.get('broker') 
port = 1883


def obtener_estado_vehiculo():
    vehicle_plate = "ABC123"
    current_steering = 130.5
    current_speed = 150.0
    current_position = (40.7128, -74.0060)  # Latitud y longitud
    current_leds = {"front": "on", "rear": "off"}
    current_ldr = 300
    current_obstacle_distance = 100

    vehicle_status = {
        "vehicle_plate": vehicle_plate,
        "current_steering": current_steering,
        "current_speed": current_speed,
        "current_position": current_position,
        "current_leds": current_leds,
        "current_ldr": current_ldr,
        "current_obstacle_distance": current_obstacle_distance
    }

    return vehicle_status


def telemetry_cryptography(vehicle_status, client):

    while True:
        try:
            # Carga de la clave privada del vehículo
            with open("./vehicle1-private-key.pem", "rb") as pem_file:
                private_key = load_pem_private_key(pem_file.read(), password=None, backend=default_backend())

            # Firma de datos
            data_sign = str(vehicle_status)
            prehashed = hashlib.sha256(data_sign.encode('utf8')).hexdigest()
            signature = private_key.sign(bytes(prehashed.encode('ascii')), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            base64Signature = base64.b64encode(signature)

            # Encriptación
            telemetry_message = {"state": vehicle_status, "signature": base64Signature.decode('utf-8')}
            fernet_key = Fernet.generate_key()  # Genera una nueva clave para Fernet
            fernet = Fernet(fernet_key)
            crypted = fernet.encrypt(str(telemetry_message).encode('utf-8'))

            # Envío de la telemetría
            client.connect()
            initial_telemetry = {"ts": int(round(time.time() * 1000)), "values": {"telemetria": crypted}}
            client.send_telemetry(initial_telemetry)
            result = client.send_telemetry(crypted)  # Enviar los datos de telemetría con el sello de tiempo
            success = result.get() == TBPublishInfo.TB_ERR_SUCCESS
            print("Resultado de la publicación de telemetría:", success)
            time.sleep(60)

        except Exception as e:
            print(f"El vehículo no está conectado. No se puede enviar telemetría: {e}")
            return



def configure_cryptography(set_key_value, mr_publickey_value, signature_value, client):
    if signature_value is None:
        print("Esperando los parámetros 'command' y 'signature'...")
        return False
    else:
        data_sign = dict()
        data_sign["set_key"] = set_key_value
        data_sign["message_router_public_key"] = mr_publickey_value
        mr_public_key = base64.b64decode(mr_publickey_value.encode('utf-8'))
        public_key = load_pem_public_key(mr_public_key, backend=default_backend())
        signature = signature_value
        signature = base64.b64decode(signature.encode('utf-8'))
        data_sign = str(data_sign).encode('utf-8')  
        try:
            public_key.verify(
                signature,
                data_sign,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print('Clave de sesión válida!')
            vehicle_status = obtener_estado_vehiculo()
            telemetry_cryptography(vehicle_status,client)
            time.sleep(60)
            return True
        except InvalidSignature:
            print('Clave de sesión NO válida!')
            return False

        
# Callback para manejar cambios en los atributos
def callback(result, *args):
    print("Se recibieron nuevos atributos: ")
    logging.debug(f"Datos Recibidos: {result}")
    set_key_value = result.get('set_key')
    mr_publickey_value = result.get('message_router_public_key')
    signature_value = result.get('signature')
    client = TBDeviceMqttClient(broker, port, token)
    configure_cryptography(set_key_value, mr_publickey_value, signature_value,client)
       

def on_attributes_change(result, exception=None):
    if exception is not None:
        logging.error("Exception: " + str(exception))
    else:
        logging.info(result)


def inicializar_cliente_mqtt(broker, port, token, secret_key, duration):
    logging.basicConfig(level=logging.DEBUG)
    client = TBDeviceMqttClient(broker, port, token)
    client.connect()
    initial_telemetry = {"ts": int(round(time.time() * 1000)), "values": {"state": "Esperando de la configuración de la sesión"}}
    client.send_telemetry(initial_telemetry)
    result = client.send_telemetry(initial_telemetry)  
    success = result.get() == TBPublishInfo.TB_ERR_SUCCESS
    print("Resultado de la publicación de telemetría:", success)  
    client.send_attributes({"atr3": "value1", "atr4": "value2"})
    # Requesting attributes
    client.request_attributes(["atr3", "atr4"], callback=on_attributes_change)
    sub_id_2 = client.subscribe_to_all_attributes(callback)
    print("Inicio de la conexión")
    
    rc = client.claim(secret_key=secret_key, duration=duration).get()
    if rc == 0:
        print("CONEXIÓN ESTABLECIDA con éxito con el servidor MQTT")
    else:
        print(f"No se pudo establecer conexión. Código de retorno: {rc}")
    
    print("Inicio de la publicación de telemetría")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.unsubscribe_from_attribute(sub_id_2)
        client.disconnect()
    return client
    

if __name__ == "__main__":
    token = token
    broker = broker 
    port = 1883    
    secret_key = api_key 
    duration = 30000
  
    try:
        client = inicializar_cliente_mqtt(broker, port, token, secret_key, duration)           
    except KeyboardInterrupt:
        print("Proceso interrumpido por el usuario")
        client.disconnect()

    except Exception as e:
        print(f"Error general: {e}")

