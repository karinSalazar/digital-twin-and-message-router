import time
import logging
import threading
import base64
import json
from dotenv import dotenv_values
from tb_rest_client.rest_client_ce import RestClientCE
from tb_rest_client.rest import ApiException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from tb_rest_client.rest_client_ce import *

# Cargamos las variables de entorno desde el archivo .env_vars
env_vars = dotenv_values('/usr/src/app/.env_vars')

# Accedemos a las variables de entorno cargadas
base_url = env_vars.get('base_url')
username = env_vars.get('username')
password = env_vars.get('password') 
client_id = env_vars.get('client_id') 


lista_dispositivos_activos = []


    
def iniciar_sesion(base_url, username, password):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(module)s - %(lineno)d - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    try:
        client = RestClientCE(base_url=base_url)
        client.login(username=username, password=password)
        logging.info("Inicio de sesión exitoso!")
        return client
    except ApiException as e:
        logging.exception("Error al iniciar sesión:", e)



def dispositivo_en_lista(nuevo_dispositivo, lista_dispositivos_activos):
    if nuevo_dispositivo in lista_dispositivos_activos:
        print("El dispositivo ya está en la lista:", nuevo_dispositivo)
        #time.sleep(60)
        return True
    else:
        print("El dispositivo no está en la lista. Agregándolo:", nuevo_dispositivo)
        lista_dispositivos_activos.append(nuevo_dispositivo)
    


def cypher_is_public_key(key, public_key):
    cyphered_messages_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cyphered_messages_key


def load_private_key(filename, password=b"your-password"):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key


def load_public_key(device_id):
    with open(device_id, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key
    

def sign_command(command_to_send, private_key, public_key):
    command_bytes = json.dumps(command_to_send).encode('utf-8')
    signature = private_key.sign(
        command_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def obtener_dispositivos_activos_de_cliente(client):
    while True:
        try:
            devices_response = client.get_customer_device_infos(customer_id=client_id, page_size=10, page=0, active=True)
            devices = devices_response.to_dict()["data"]

            # Verificar si no hay dispositivos activos
            if not devices:
                # devices_response = client.get_customer_device_infos(customer_id=client_id, page_size=10, page=0, active=False)
                # devices = devices_response.to_dict()["data"]
                # lista_dispositivos_activos.remove(devices)
                # clave_vacia = ""
                # configuracion_vacia = {}
                # command_to_send = {
                #         "set_key": clave_vacia,
                #         "message_router_public_key": configuracion_vacia,
                #     }
                # client.save_entity_attributes_v2(entity_id=entity, scope="SHARED_SCOPE", body=command_to_send) 
                print("No hay dispositivos activos. Deteniendo el bucle.")
                break
            
            for item in devices:
                device_id = item["id"]["id"]
                
                if dispositivo_en_lista(device_id, lista_dispositivos_activos):
                    key = Fernet.generate_key()
                    with open(str(device_id) + ".key", "wb") as key_file:
                        key_file.write(key)
                    print("Key to set: {}".format(key))
                                    
                    public_key = load_public_key("message-router-rsa.pub") 
                    private_key = load_private_key("message-router-rsa.pem", password=b"your-password")
                    
                    cyphered_messages_key = cypher_is_public_key(key, public_key)
                    
                    command_to_send = {
                        "set_key": base64.b64encode(cyphered_messages_key).decode('utf-8'),
                        "message_router_public_key": base64.b64encode(public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )).decode('utf-8')
                    }
                    command_to_send["signature"] = sign_command(command_to_send, private_key, public_key)
                    signature_base64 = base64.b64encode(command_to_send["signature"]).decode('utf-8')
                    command_to_send["signature"] = signature_base64   

                    entity = EntityId(id=device_id, entity_type="DEVICE")
                    client.save_entity_attributes_v2(entity_id=entity, scope="SHARED_SCOPE", body=command_to_send) 
                    print("lista_dispositivos_activos ANTES: ", lista_dispositivos_activos)
                    if device_id not in lista_dispositivos_activos:
                        lista_dispositivos_activos.append(device_id)
                        time.sleep(60)
                    else:
                        print("El dispositivo ya está en la lista de dispositivos activos.")
                        #time.sleep(60) 
                        break
                else: 
                    print("No hay más dispositivos para procesar. Terminando el bucle.")
                    #time.sleep(60)
                    
                   
        except ApiException as e:
            print("Error:", str(e)) 

      
def monitorear_conexion_desconexion():
    while True:
        print("Monitoreando conexión/desconexión de Gemelos Digitales de vehículos...")
        


def monitorear_recepcion_telemetria():
    while True:
        print("Monitoreando recepción de telemetría...")
        time.sleep(5)  


if __name__ == "__main__":
    # Generar par de clave pública y privada para el Message Router
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_pass = b"your-password"
    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Guardar la clave privada en un archivo
    with open("./message-router-rsa.pem", "wb") as private_key_file:
        private_key_file.write(encrypted_pem_private_key)
    
    # Guardar la clave pública en un archivo
    with open("message-router-rsa.pub", "wb") as public_key_file:
        public_key_file.write(pem_public_key)
    # Iniciar sesión
    client = iniciar_sesion(base_url, username, password)
    
    if client:
        # Crear y lanzar el hilo para obtener dispositivos activos cada minuto
        thread_actualizacion = threading.Thread(target=obtener_dispositivos_activos_de_cliente, args=(client,), daemon=True)
        thread_actualizacion.start()

        # Crear los threads Daemon para monitorizar la conexión/desconexión y la recepción de telemetría
        # thread_conexion_desconexion = threading.Thread(target=monitorear_conexion_desconexion, daemon=True)
        # thread_recepcion_telemetria = threading.Thread(target=monitorear_recepcion_telemetria, daemon=True)

        # # Iniciar los threads
        # thread_conexion_desconexion.start()
        # thread_recepcion_telemetria.start()

        # Esperar a que los hilos terminen (no deberían hacerlo debido a que son demonios)
        thread_actualizacion.join()