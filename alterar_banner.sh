#!/usr/bin/env/bash

## INFO ##
## NOME.............: conf_banner.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Atualiza o banner do sistema removendo as informações
## DATA DA CRIAÇÃO..: 18/04/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3
## Git Hub..........: https://github.com/bflima

# Declaração de variáveis
ISSUE=$(find /etc/ -iname issue)
ISSUENET=$(find /etc/ -iname issue.net)
MOTD=$(find /etc/ -iname motd)
MSG_BANNER='Acesso ao sistema monitorado'

echo "$MSG_BANNER" > "$ISSUE"
echo "$MSG_BANNER" > "$ISSUENET"
echo "$MSG_BANNER" > "$MOTD"
