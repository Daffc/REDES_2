'''
Programa: Biblioteca Auxiliar de Funções de criptografia utilizada por cliente e servidor TCP/IP.

Autores:    Douglas Affonso Clementino GRR20175877
            Rafael de Paulo Dias GRR20176556
            
Data da última Modificação: 31/07/2021
'''

from des import DesKey
from random import randint
import sympy


TAMANHO_CHAVE = 8   # Tamanho de chaves Utilizado.
MAX_RAND_INT = 1024
MIN_PRIME = 1
MAX_PRIME = 256

# Gera chave DES a partir de inteiro 'chave'
def geraChaveDES(chave):
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
def geraPrimoRandomico(antigo_primo):

    # Gera novo número primo
    novo_primo = sympy.randprime(MIN_PRIME, MAX_PRIME)

    # Enquanto novo novo_primo == antigo_primo, gerar outro número primo.
    while (novo_primo == antigo_primo):
        novo_primo = sympy.randprime(MIN_PRIME, MAX_PRIME)

    return novo_primo