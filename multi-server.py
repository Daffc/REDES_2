#!/usr/bin/env python3.9
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

import criptografia as cript

# TAMANHO MÁXIMO DE MENSAGEM.
MAX_DATA=1024
staticModulusPrime = 5
# staticChavePrivadaServidor = 15


def tratandoRecebimento(data, recv_data):
    # Caso chave de criptografia não tenha sido definida.
    if(not data.chaveDH):
        # Caso não tenha sido definido o 'basePrime' (enviado pelo cliente), menságem atual deverá conte-lo.
        if(not data.basePrime):
            # Vinculando 'basePrime' a estrutura de dados 'dados' de conexão.
            data.basePrime = int.from_bytes(recv_data , "big")

            # Definindo 'modulusPrime' e enviando para Cliente desta conexão.
            # data.modulusPrime = staticModulusPrime # Caso tenha que gerar randômico, colocar aqui.

            data.modulusPrime = cript.geraPrimoRandômico(data.basePrime)
            data.outb = bytes([data.modulusPrime])

        # Caso bases já estejam definidas, menságem conterá chave pública.
        else:

            # Recebendo Chave pública de cliente.
            chavePublicaCliente = int.from_bytes(recv_data , "big")

            # DefinincoCave Publica servidor.
            chavePrivadaServidor = cript.geraInteiroRandomico() #Caso tenha que gerar randômico, colocar aqui.
            
            # Calculando chave privada e armazenando chave de criptografia.
            data.chaveDH = (chavePublicaCliente ** chavePrivadaServidor) % data.basePrime

            # Gerando Chave DES.
            data.chaveDES = cript.geraChaveDES(data.chaveDH)

            # Calculando e retornando Chave Pública de servidor e retornando para cliente.
            chavePublicaServidor = (data.modulusPrime ** chavePrivadaServidor) % data.basePrime
            data.outb = bytes([chavePublicaServidor])
    else:
        
        # Decriptografando Mensagem
        mensagem = cript.decriptografar(data.chaveDES, recv_data)
        
        # Operações com menságem.
        print('mensagem', mensagem)

        resposta = str.encode(f'RESPONDENDO {data.addr} COM ({mensagem}) ')

        # Define Resposta.
        data.outb += cript.criptografar(data.chaveDES, resposta)


# Tratando de receber dados para conexões previamente iniciadas.
def atenderConexao(key, mask):

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
            print('Enviando: ', repr(data.outb), 'para', data.addr)

            # Envia menságem e ajusta ponteiro de buffer.
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]
        
            print("data.basePrime", data.basePrime, "data.modulusPrime", data.modulusPrime, "data.chaveDH", data.chaveDH)

def defineNovaConexao(sock):
    
    # Definindo socket para nova conexão.
    conn, endereco = sock.accept()
    print(f'Definindo nova conexão ({endereco})')

    # Colocando socket de nova conexão em modo não-bloqueante.
    conn.setblocking(False)

    #Gerador de Primo

    # Definindo objeto para manipulação de conexão criada.
    data = types.SimpleNamespace(
                                addr=endereco,      # Endereço de cliente.
                                inb=b'',            # Dados recebidos.
                                outb=b'',           # Dados enviados.
                                modulusPrime=None,  # Número primo de cifragem do servidor.
                                basePrime=None,     # Número Primo se cigragem do cliente. 
                                chaveDH=None,       # Chave privada DH.
                                chaveDES=None)      # Chave de para criptografar/decriptografar DES.
    
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
                defineNovaConexao(key.fileobj)

            # Caso contrário, objetos de arquivo selecionado é o de conexão já existente.
            else:
                atenderConexao(key, mask)