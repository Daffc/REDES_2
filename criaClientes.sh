#!/usr/bin/env bash
SERVIDOR=$1;
PORTA=$2;
N_CLIENTES=$3;

mkdir clientOutput;
for i in $(seq 1 $N_CLIENTES); do  
    ./cliente.py $SERVIDOR $PORTA > clientOutput/cliente$i\_output.txt &  
done; 

wait;