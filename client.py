#!/usr/bin/env python3

'''
Programa: Cliente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de cirptografia para troca de chaves Diffie-Hellman.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.
            
Data da última Modificação: 22/07/2021
'''

import socket
import argparse
from random import randint

import criptografia as cript

# TAMANHO MÁXIMO DE MENSAGEM.
MAX_DATA=1024
# staticBasePrime = 23
# staticSecretInteger = 6

# Recuperando argumentos de entrada 
def parsingArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("SERVER", help="Indica o IP da interface de rede utilizada pelo servidor.")
    parser.add_argument("PORT", help="Indica a porta utilizada pelo servidor.")
    args = parser.parse_args()

    return args.SERVER, int(args.PORT)



if __name__ == "__main__":
    SERVER, PORT = parsingArguments()

    # # ABRINDO VÁRIAS CONEXÕES E FEICHANDO SOMENTE APÓS COMUNICAÇÃO (DEBUG)
    # s = []
    # for i in range(5):
    #     s.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    #     s[i].connect((SERVER, PORT))

    #     mensagem = f"REQUEST CONEXAO '{i}'."

    #     s[i].sendall(str.encode(mensagem))
    #     data = s[i].recv(MAX_DATA)
    #     print('Received', repr(data))

    # # ENVIANDO 10 MENSÁGENS POR CONEXÕES RANDÔMICAS.
    # for i in range(10):

    #     rand = randint(0, 4)
    #     mensagem = f"MENSAGEM RANDOMICA: '{i}', CONEXAO: '{rand}'."
    #     s[rand].sendall(str.encode(mensagem))
    #     data = s[rand].recv(MAX_DATA)
    #     print('Received', repr(data))

    # # FECHANDO CONEXÕES.
    # for i in range(5):
    #     s[i].close()


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER, PORT))

    # basePrime = staticBasePrime # Caso tenha que gerar randômico, colocar aqui.
    basePrime = cript.geraPrimoRandômico(None)
    s.sendall(bytes([basePrime]))

    data = s.recv(MAX_DATA)
    modulusPrime = int.from_bytes(data, "big")
    
    print("basePrime", basePrime, "modulusPrime", modulusPrime)


    chavePrivadaCliente = cript.geraInteiroRandomico() #Caso tenha que gerar randômico, colocar aqui.
    A = (modulusPrime ** chavePrivadaCliente) % basePrime
    s.sendall(bytes([A]))

    data = s.recv(MAX_DATA)
    B = int.from_bytes(data, "big")
    chaveDH = (B ** chavePrivadaCliente) % basePrime

    print("chaveDH", chaveDH)


    chaveDES = cript.geraChave(chaveDH)
    mensagem = cript.criptografar(chaveDES, b"Qualquer mensagem meu bom")
    s.sendall(mensagem)

    data = s.recv(MAX_DATA)
    data_2 = cript.decriptografar(chaveDES, data)
    print(data, repr(data_2))


    s.close()
