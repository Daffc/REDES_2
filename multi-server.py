#!/usr/bin/env python3
'''
Programa: Servidor Concorrente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de cirptografia para troca de chaves Diffie-Hellman.

Autores:    Douglas Affonso Clementino.
            Rafael de Paulo Dias.

Data da última Modificação: 22/07/2021
'''

import selectors
import types
import argparse
import socket

MAX_DATA=1024


# Tratando de receber dados para conexões previamente iniciadas.
def service_connection(key, mask):

    # Recuperando objeto de arquivo e dados de conexão.
    sock = key.fileobj
    data = key.data

    # Caso socket esteja pronto para ser lido.
    if mask & selectors.EVENT_READ:
        # Lê dados de comunicação.
        recv_data = sock.recv(MAX_DATA)

        # Caso existam dados, armazená-los em 'data.outb'.
        if recv_data:
            data.outb += recv_data

        # Caso existam dados, armazená-los em 'data.outb'.
        else:
            print('Terminando conexão com {data.addr}')
            sel.unregister(sock)    # Removendo objeto de arquivo de multiplexador.
            sock.close()            # Fechando socket.

    # Caso socket esteja pronto para ser escrito.
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print('Enviando: ', repr(data.outb), 'para', data.addr)
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]


def accept_wrapper(sock):
    
    # Definindo socket para nova conexão.
    conn, endereco = sock.accept()
    print(f'Definindo nova conexão ({endereco})')

    # Colocando socket de nova conexão em modo não-bloqueante.
    conn.setblocking(False)

    # Definindo objeto para manipulação de conexão criada.
    data = types.SimpleNamespace(
                                addr=endereco,  # Endereço de cliente.
                                inb=b'',        # Dados recebidos.
                                outb=b'',       # Dados enviados.
                                sprime=2,       # Número primo de cifragem do servidor.
                                cprime=None,    # Número Primo se cigragem do cliente. 
                                ckey=None)      # Chave privada.
    
    # Definindo eventos para nova conesão (Leitura e Escrita).
    events = selectors.EVENT_READ | selectors.EVENT_WRITE

    # Registrando nova conexão em multiplexador I/O 
    # (objetos de arquivo, lista de eventos, dados para manipulação).
    sel.register(conn, events, data=data)


# Recuperando argumentos de entrada 
def parsingArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("SERVER_IP", help="Indica o IP da interface de rede utilizada pelo servidor.")
    parser.add_argument("PORT", help="Indica a porta utilizada pelo servidor.")
    args = parser.parse_args()

    return args.SERVER_IP, int(args.PORT)

if __name__ == "__main__":

    # Recuperando HOST e servidor para socket.    
    HOST, PORT = parsingArguments()
    
    # Definindo seletor de objetos de arquivo (abstração para file descriptor de sockets). 
    sel = selectors.DefaultSelector()

    # Definindo socket de escuta de servidor.
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Vinculando socket de escuta a porta e interface selecionados.
    listening_sock.bind((HOST, PORT))

    # Inicializando socket de escuta.
    listening_sock.listen()

    print(f'Escutando interface \'{HOST}\' em porta \'{PORT}\'...')

    # Colocando socket de escuta em modo não-bloqueante.
    listening_sock.setblocking(False)

    # Registrando socket de escuta em multiplexador de objetos de arquivo. 
    sel.register(listening_sock, selectors.EVENT_READ, data=None)

    # Loop a espera de novas menságens.
    while True:

        # Caso algum dos objetos de arquivo registrados em 'sel' esteja pronto
        # (socket de escuta ou conexões que já tenham sido registras), selecioná-lo.
        events = sel.select(timeout=None)

        # Multiplexando recebimento de dados
        for key, mask in events:
            # Caso dados estejam vazios, objetos de arquivo selecionado é o de 'listening_sock', 
            # ou seja, nova solicitação para abertura de conexão. 
            if key.data is None:
                accept_wrapper(key.fileobj)

            # Caso contrário, objetos de arquivo selecionado é o de conexão já existente.
            else:
                service_connection(key, mask)