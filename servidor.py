#!/usr/bin/env python3.9
'''
Programa: Servidor Concorrente TCP/IP usando socket 'SOCK_STREAM' aplicando metodo de troca de chaves Diffie-Hellma para aplicação de criptografia.

Autores:    Douglas Affonso Clementino GRR20175877
            Rafael de Paulo Dias GRR20176556
            
Data da última Modificação: 31/07/2021
'''

import selectors
import types
import argparse
import socket
from dataclasses import dataclass
from des import DesKey

import criptografia as cript

@dataclass()
class ClientConnection:
    addr:str                    # Endereço de cliente.
    inb:bytes = b''             # Dados recebidos.
    outb:bytes = b''            # Dados enviados.
    basePrime: int = None       # Número primo base para Diffie-Hellman.
    modulusPrime: int = None    # Número Primo modulo para Diffie-Hellman. 
    publicKey: int = None       # Chave publica de servidor para conexão.   
    privateKey: int = None      # Chave privada de servidor para conexão.
    sharedSecretKey: int = None # Chave secreta compartilhada Diffie-Hellman.
    desKey: DesKey = None       # Chave de para criptografar/decriptografar DES.


# TAMANHO MÁXIMO DE MENSAGEM.
MAX_DATA=1024


def tratandoRecebimento(data, recv_data):
    # Caso chave de criptografia não tenha sido definida.
    if(not data.sharedSecretKey):
        # Caso não tenha sido definido o 'basePrime' (enviado pelo cliente), menságem atual deverá conte-lo.
        if(not data.basePrime):

            # Vinculando 'basePrime' a estrutura de dados 'dados' de conexão.
            data.basePrime = int.from_bytes(recv_data , "big")
            print(f'\tRecebendo BasePrime de Cliente: {data.addr}')
            print(f'\t\tBasePrime: {data.basePrime}')

            
            # Definindo 'modulusPrime' e enviando para Cliente desta conexão.
            data.modulusPrime = cript.geraPrimoRandomico(data.basePrime)
            print(f'\t\tGerando modulusPrime: {data.modulusPrime}')
            data.outb = bytes([data.modulusPrime])

        # Caso bases já estejam definidas, menságem conterá chave pública.
        else:

            print(f'\tRecebendo Chave Publica de Cliente: {data.addr}')

            # Recebendo Chave pública de cliente.
            publicClientKey = int.from_bytes(recv_data , "big")
            print(f'\t\tpublicClientKey: {publicClientKey}')


            # DefinincoCave Privada servidor.
            data.privateKey = cript.geraInteiroRandomico() #Caso tenha que gerar randômico, colocar aqui.
            
            print(f'\t\tGerando Chave privada (privateKey) servidor: {data.privateKey}')
            
            
            # Calculando chave privada compartilhada e armazenando chave de criptografia.
            data.sharedSecretKey = (publicClientKey ** data.privateKey) % data.basePrime
            print(f'\t\tDefinindo Chave compartilhada (sharedSecretKey): {data.sharedSecretKey}')

            # Gerando Chave DES.
            data.desKey = cript.geraChaveDES(data.sharedSecretKey)
            print(f'\t\tGerando Chave de criptografia DES (desKey): {data.desKey}')

            # Calculando e retornando Chave Pública de servidor e retornando para cliente.
            data.publicKey = (data.modulusPrime ** data.privateKey) % data.basePrime
            print(f'\t\tGerando Chave Pública (publicKey) de servidor: {data.publicKey}')
            data.outb = bytes([data.publicKey])
        print(f'\t\t{data}')

    else:

        print(f'\tRecebendo Menságem Criptografada de Cliente: {data.addr}')
        
        # Decriptografando Mensagem
        mensagem = recv_data
        mensagem_decript = cript.decriptografar(data.desKey, recv_data)

        print('\t\tMensagem Cripto: ', repr(mensagem))
        print('\t\tMensagem Decripto: ', repr(mensagem_decript))


        # Operações com menságem.
        resposta = f'RESPONDENDO {data.addr} COM ({mensagem_decript})'
        resposta_encript = cript.criptografar(data.desKey, str.encode(resposta))

        print('\t\tDefinindo Menságem Desposta: ')
        print('\t\t\tResposta Original: ', repr(resposta))
        print('\t\t\tResposta Criptografada: ', repr(resposta_encript))
        


        # Define Resposta.
        data.outb += resposta_encript



# Tratando de receber dados para conexões previamente iniciadas.
def atenderConexao(sel, key, mask):

    # Recuperando objeto de arquivo e dados de conexão.
    sock = key.fileobj
    data = key.data

    # Caso socket esteja pronto para ser lido.
    if mask & selectors.EVENT_READ:
        # Lê dados de comunicação.
        recv_data = sock.recv(MAX_DATA)

        # Caso existam dados, tratar de comunicação.
        if recv_data:
            tratandoRecebimento(data, recv_data)

        # Caso não existam dados, fechar conexão.
        else:
            print(f'Terminando conexão com {data.addr}')
            sel.unregister(sock)    # Removendo objeto de arquivo de multiplexador.
            sock.close()            # Fechando socket.

    # Caso menságem esteja pronta para ser enviada.
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print('\t\tEnviando: ', repr(data.outb), 'para', data.addr)

            # Envia menságem e ajusta ponteiro de buffer.
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]
        
def defineNovaConexao(sel, sock):
    
    # Definindo socket para nova conexão.
    conn, endereco = sock.accept()
    print(f'Definindo nova conexão ({endereco})')

    # Colocando socket de nova conexão em modo não-bloqueante.
    conn.setblocking(False)

    #Gerador de Primo

    # Definindo objeto para manipulação de conexão criada.
    data = ClientConnection(endereco)
    
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
    
    print("==========================================================================")
    print(f" Inicializando Servidor em interface \'{HOST}\' em porta \'{PORT}\'  ")    
    print("==========================================================================")

    # Definindo seletor de objetos de arquivo (abstração para file descriptor de sockets). 
    sel = selectors.DefaultSelector()

    # Definindo socket de escuta de servidor.
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Vinculando socket de escuta a porta e interface selecionados.
    listening_sock.bind((HOST, PORT))

    # Inicializando socket de escuta.
    listening_sock.listen()

    print('Definindo Socket de Escuta... ', end='')
    # Colocando socket de escuta em modo não-bloqueante.
    listening_sock.setblocking(False)
    print('OK')

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
                defineNovaConexao(sel, key.fileobj)

            # Caso contrário, objetos de arquivo selecionado é o de conexão já existente.
            else:
                atenderConexao(sel, key, mask)