#!/usr/bin/env bash

## INFO ##
## NOME.............: bloq_ssh.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Atualiza o banner do sistema removendo as informações
## DATA DA CRIAÇÃO..: 29/04/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3
## Git Hub..........: https://github.com/bflima

# Verificar se arquivo auth.log existe
SSH_LOG=$(find /var/log/ -iname auth.log)
[[ -f $SSH_LOG ]] || { echo "Arquivo $SSH_LOG nao encontrado, Favor verificar..." ; exit 1 ; }

# Filtrar IPS gravados no log
IP_BLOQ=$(cat "$SSH_LOG" | grep -i sshd | grep -i failed | grep -i invalid | awk '{print $13}'| sort | uniq -c)
IP_BLOQ_ADDR=$(echo "$IP_BLOQ"  | awk '{print $2}')
IP_BLOQ_COUNT=$(echo "$IP_BLOQ" | awk '{print $1}')

# Ips Cadastrados para Whistelist
WHITELIST='189.108.86.210 200.200.200.200'

# Verificar se iptables existe
IPT=$(which iptables)
[[ -f $IPT ]] || { echo "$IPT nao encontrado, Favor verificar..." ; exit 1 ; }

for WHITE in $WHITELIST
  do
    "$IPT" -C INPUT -p tcp -s $WHITE -j ACCEPT || "$IPT" -I INPUT 1 -p tcp -s $WHITE -j ACCEPT

  done


for IP in $(cat "$SSH_LOG" | grep sshd | grep Failed | grep invalid | awk '{print $13}'| sort | uniq)
  do
    BLOQ=$(cat "$SSH_LOG" | grep invalid | grep $IP | wc -l)
    if [ $BLOQ -gt 3 ]
      then
        "$IPT" -C INPUT -p tcp -s $IP -j DROP || "$IPT" -A INPUT -p tcp -s $IP -j DROP
    fi
  done
