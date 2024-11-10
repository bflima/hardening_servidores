#!/usr/bin/env bash

## INFO ##
## NOME.............: geoip.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Script informa o endereço ip e país de origem.
## DEPENDENCIAS.....: geoip-bin (comando que realiza a consulta de geolocalização dos ips)
## DATA DA CRIAÇÃO..: 16/10/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3

# Verifica se o comando geoip-bin está instalado
command -v geoiplookup || apt install -y geoip-bin

# Localiza e armazena a variável auth.log
AUTH_LOG=$(find /var/ -iname auth.log)

# Localização de arquivos
ARQ_GEO_LOCAL='/tmp/geoip_local.txt'
ARQ_GEO_IP='/tmp/geoip_ip.txt'

# Expressão regular simples para localizar endereços de ip
IPS=$(grep -E -o '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$AUTH_LOG" | sort -u)

: > "$ARQ_GEO_LOCAL"
: > "$ARQ_GEO_IP"

for ip in $IPS
  do
     geoiplookup "$ip"  >> "$ARQ_GEO_LOCAL"
     echo        "$ip"  >> "$ARQ_GEO_IP"
done

clear 

# Informar total de ips de países registrados
sort -nr <  "$ARQ_GEO_LOCAL" | uniq -c | grep -v '#'
grep -E -o '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$ARQ_GEO_IP" | uniq -c | sort -nr
