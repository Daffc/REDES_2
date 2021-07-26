#!/usr/bin/env python3

'''
Programa: Cliente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de cirptografia para troca de chaves Diffie-Hellman.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.
            
Data da última Modificação: 22/07/2021

'''

import socket
import argparse

# Recuperando argumentos de entrada 
def parsingArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("SERVER", help="Indica o IP da interface de rede utilizada pelo servidor.")
    parser.add_argument("PORT", help="Indica a porta utilizada pelo servidor.")
    args = parser.parse_args()

    return args.SERVER, int(args.PORT)



if __name__ == "__main__":
    SERVER, PORT = parsingArguments()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER, PORT))
        s.sendall(b'Hello, world')
        data = s.recv(1024)

    print('Received', repr(data))