#!/usr/bin/env python3.9

'''
Programa: Cliente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de troca de chaves Diffie-Hellma para aplicação de criptografia.

Autores:    Douglas Affonso Clementino GRR20175877
            Rafael de Paulo Dias GRR20176556
            
Data da última Modificação: 31/07/2021
'''

import socket
import argparse
from random import randint 
from des import DesKey
from dataclasses import dataclass, fields
from time import sleep

import criptografia as cript



# TAMANHO MÁXIMO DE MENSAGEM.
MAX_DATA=1024

@dataclass()
class Connection:
    id: int                         # Indenficador deconexão.
    socket: socket.socket           # Socket para comunicação.
    basePrime: int = None           # Número primo base para Diffie-Hellman.
    modulusPrime: int = None        # Número Primo modulo para Diffie-Hellman. 
    publicKey: int = None           # Chave publica de cliente para conexão.   
    privateKey: int = None          # Chave privada de cliente para conexão.
    sharedSecretKey: int = None     # Chave secreta compartilhada Diffie-Hellman.
    desKey: DesKey = None           # Chave de para criptografar/decriptografar DES.

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

    # Inicializando objeto de conexão.
    conn = Connection(  randint(0, 1000), 
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM), 
                        None)

    # Solicitando iniciação de conexão com servidor SERVER em porta PORT.
    conn.socket.connect((SERVER, PORT))
    print('\n'.join("%s: %s" % item for item in vars(conn).items()))
    
    print("==========================================================================")
    print("                        Trocando Números Primos                           ")    
    print("==========================================================================")

    # Gerando Valor Primo de base para Diffie-Hellman.
    conn.basePrime = cript.geraPrimoRandomico(None)

    # Enviando pribmo base para servidor.
    conn.socket.sendall(bytes([conn.basePrime]))

    # Recebendo Primo de módulo para  Diffie-Hellman de  servidor.
    data = conn.socket.recv(MAX_DATA)
    conn.modulusPrime = int.from_bytes(data, "big")

    # Imprimindo insância de Connection.
    print('\n'.join("%s: %s" % item for item in vars(conn).items()))
    

    print("==========================================================================")
    print("           Definindo Chaves Publicas, Privadas e Diffie–Hellman           ")    
    print("==========================================================================")

    # Gerando Chave Privada Diffie-Hellman.
    conn.privateKey = cript.geraInteiroRandomico()

    # Gerando Chave Pública Diffie-Hellman.
    conn.publicKey = (conn.modulusPrime ** conn.privateKey) % conn.basePrime

    # Enviando Chave Pública a Servidor.
    conn.socket.sendall(bytes([conn.publicKey]))

    # Recebendo Chave Pública de Servidor.
    data = conn.socket.recv(MAX_DATA)
    publicServerKey = int.from_bytes(data, "big")

    # Calculando Chave Secreta Compartilhada.
    conn.sharedSecretKey = (publicServerKey ** conn.privateKey) % conn.basePrime

    # Imprimindo insância de Connection.
    print('\n'.join("%s: %s" % item for item in vars(conn).items()))

    print("==========================================================================")
    print("                           Definindo Chaves DES                           ")
    print("==========================================================================")
    
    # Gerando Chave de criptografia DES sobre chave secreta compartilhada.
    conn.desKey = cript.geraChaveDES(conn.sharedSecretKey)
    print('\n'.join("%s: %s" % item for item in vars(conn).items()))


    print("==========================================================================")
    print("                     Trocando Menságens Criptografadas                    ")
    print("==========================================================================")

    # ENVIANDO 5 MENSÁGENS POR CONEXÕES RANDÔMICAS.
    for i in range(5):

        print(f'Troca Menságens Cirptografadas Ordem {i}:')

        # Definindo Menságem e criptografando-a.
        mensagem = f"MENSAGEM '{i}', ID: '{conn.id}'."
        mensagem_cript = cript.criptografar(conn.desKey, str.encode(mensagem))
        # Enviando Menságem
        conn.socket.sendall(mensagem_cript)

        print(f'\tEnviando Menságem:')
        print('\t\tMensagem Cripto: ', repr(mensagem_cript))
        print('\t\tMensagem Decripto: ', repr(str.encode(mensagem)))

        # Recebendo Resposta e decriptografando-a.
        data = conn.socket.recv(MAX_DATA)
        real_data = cript.decriptografar(conn.desKey, data) 
        print(f'\tRecebendo Menságem:')
        print('\t\tRespota Cripto: ', repr(data))
        print('\t\tRespota  Decripto: ', repr(real_data))


    print("==========================================================================")
    print("                           Fechando Conexão                               ")
    print("==========================================================================")
    # Fechando Conexão.
    conn.socket.close()

