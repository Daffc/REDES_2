#!/usr/bin/env python3.9

'''
Programa: Cliente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de cirptografia para troca de chaves Diffie-Hellman.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.
            
Data da última Modificação: 22/07/2021
'''

import socket
import argparse
from random import randint 
from des import DesKey
from dataclasses import dataclass
from time import sleep

import criptografia as cript



# TAMANHO MÁXIMO DE MENSAGEM.
MAX_DATA=1024
N_CONN = 4


@dataclass()
class Connection:
    id: int
    socket: socket.socket
    basePrime: int
    modulusPrime: int
    privateKey: int
    privateKey: int
    sharedSecretKey: int
    desKey: DesKey

# Recuperando argumentos de entrada 
def parsingArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("SERVER", help="Indica o IP da interface de rede utilizada pelo servidor.")
    parser.add_argument("PORT", help="Indica a porta utilizada pelo servidor.")
    args = parser.parse_args()

    return args.SERVER, int(args.PORT)


if __name__ == "__main__":
    SERVER, PORT = parsingArguments()

    print("==========================================================================")
    print("                             Iniciando Conexões                           ")    
    print("==========================================================================")
    sleep(randint(500, 1000) / 1000)

    conn = Connection(  randint(0, 1000), 
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM), 
                        None,
                        None,
                        None,
                        None,
                        None)

    conn.socket.connect((SERVER, PORT))
    print(conn)
    
    print("==========================================================================")
    print("                        Trocando Números Primos                           ")    
    print("==========================================================================")
    sleep(randint(500, 1000) / 1000)

    conn.basePrime = cript.geraPrimoRandômico(None)
    conn.socket.sendall(bytes([conn.basePrime]))

    data = conn.socket.recv(MAX_DATA)
    conn.modulusPrime = int.from_bytes(data, "big")
    print(conn)
    

    print("==========================================================================")
    print("           Definindo Chaves Publicas, Privadas e Diffie–Hellman           ")    
    print("==========================================================================")
    sleep(randint(500, 1000) / 1000)
    conn.privateKey = cript.geraInteiroRandomico()
    conn.publicKey = (conn.modulusPrime ** conn.privateKey) % conn.basePrime

    conn.socket.sendall(bytes([conn.publicKey]))

    data = conn.socket.recv(MAX_DATA)
    publicServerKey = int.from_bytes(data, "big")
    conn.sharedSecretKey = (publicServerKey ** conn.privateKey) % conn.basePrime
    print(conn)

    print("==========================================================================")
    print("                           Definindo Chaves DES                           ")
    print("==========================================================================")
    conn.desKey = cript.geraChaveDES(conn.sharedSecretKey)
    print(conn)


    print("==========================================================================")
    print("                     Trocando Menságens Criptografadas                    ")
    print("==========================================================================")

    # ENVIANDO 10 MENSÁGENS POR CONEXÕES RANDÔMICAS.
    for i in range(10):
        sleep(randint(500, 1000) / 1000)

        mensagem = f"MENSAGEM '{i}', CONEXAO: '{conn.id}'."
        mensagem_cript = cript.criptografar(conn.desKey, str.encode(mensagem))
        conn.socket.sendall(mensagem_cript)


        data = conn.socket.recv(MAX_DATA)
        real_data = cript.decriptografar(conn.desKey, data) 
        print(f"CONEXÃO: {conn.id}\t Mensagem: {i}")
        print('\t', 'Mensagem Cripto: ', repr(data))
        print('\t', 'Mensagem Decripto: ', repr(real_data))


    print("==========================================================================")
    print("                          Fechando Conexões                               ")
    print("==========================================================================")
    conn.socket.close()

