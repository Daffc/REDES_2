#!/usr/bin/env python3

'''
Programa: Servidor TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de cirptografia para troca de chaves Diffie-Hellman.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.
            
Data da última Modificação: 22/07/2021
'''
import argparse
import socket


# Recuperando argumentos de entrada 
def parsingArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("SERVER_IP", help="Indica o IP da interface de rede utilizada pelo servidor.")
    parser.add_argument("PORT", help="Indica a porta utilizada pelo servidor.")
    args = parser.parse_args()

    return args.SERVER_IP, int(args.PORT)

if __name__ == "__main__":
    
    HOST, PORT = parsingArguments()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            con, addr = s.accept()
            with con:
                print('Connected by', addr)
                while True:
                    data = con.recv(1024)
                    if not data:
                        break
                    con.sendall(data)

