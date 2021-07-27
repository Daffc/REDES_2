'''
Programa: Biblioteca Auxiliar de Funções de criptografia utilizada por cliente e servidor TCP/IP.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.
            
Data da última Modificação: 22/07/2021
'''

from des import DesKey
from random import randint
import sympy


TAMANHO_CHAVE = 8   # Tamanho de chaves Utilizado.
MAX_RAND_INT = 1024
MIN_PRIME = 2
MAX_PRIME = 256


# Gera chave DES a partir de inteiro 'chave'
def geraChave(chave):
    return DesKey(chave.to_bytes(TAMANHO_CHAVE, byteorder='big'))

# Criptografa mensagem em bytes 'byte_decriptado' utilizando chave DES 'chaveDES'. 
def criptografar(chaveDES, byte_decriptado):
    return  chaveDES.encrypt(byte_decriptado, padding=True)

# Decriptografa bytes 'byte_encriptado' utilizando chave DES 'chaveDES'
def decriptografar(chaveDES, byte_encriptado):
    return  chaveDES.decrypt(byte_encriptado, padding=True)

# Gerando Número Inteiro Randômico
def geraInteiroRandomico():
    return randint(1, MAX_RAND_INT)

# Gerando Número Primo Randômico
def geraPrimoRandômico():
    return sympy.randprime(MIN_PRIME, MAX_PRIME)