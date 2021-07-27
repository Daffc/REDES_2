#!/usr/bin/env bash
SERVIDOR=$1;
PORTA=$2;
N_CLIENTES=$3;

mkdir clientOutput;
for i in $(seq 1 $N_CLIENTES); do  
    ./cliente_randomico.py $SERVIDOR $PORTA > clientOutput/client$i\_output.txt &  
done; 

wait;