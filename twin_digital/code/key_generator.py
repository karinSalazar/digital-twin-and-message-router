import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.serialization as serialization

def main():

    # Genera una clave privada RSA
    key = RSA.generate_private_key(public_exponent=65537, key_size=2048)

    # Codifica la clave privada en formato PEM
    privatekey = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption(),
    )
    # Descodifica la clave privada a una cadena
    privatekey = privatekey.decode('utf-8')
    with open('vehicle1-private-key.pem', 'w') as prv_file:
        print(privatekey, file=prv_file)

    # Genera una clave pública a partir de la clave privada
    publickey = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    # Descodifica la clave pública a una cadena
    publickey = publickey.decode('utf-8')
    with open('vehicle1-public-key.pem', 'w') as pub_file:
        print(publickey, file=pub_file)

    
if __name__ == "__main__":
    main()