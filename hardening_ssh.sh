#!/usr/bin/env bash

## INFO ##
## NOME.............: bloq_ssh.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Hardening no arquivo ssh, permitindo acesso somente ao usuário cadastrado,
## cifras ajustadas no arquivo de configuração, site usasdo para testes https://www.sshaudit.com/
## DATA DA CRIAÇÃO..: 29/04/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3
## Git Hub..........: https://github.com/bflima

SSH_CONFIG=$(find /etc -iname sshd_config)
SSH_PORT="10443"

# Hardening ssh
which /usr/sbin/sshd || { apt-update -y ; apt install openssh-server ; }

cp "$SSH_CONFIG"{,.bak}

sed -i "s/^#Port.*/Port $SSH_PORT/"                             "$SSH_CONFIG"
sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 300/'     "$SSH_CONFIG"
sed -i 's/^#MaxSessions.*/MaxSessions 2/'                       "$SSH_CONFIG"
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/'                     "$SSH_CONFIG"
sed -i 's/^#Compression.*/Compression no/'                      "$SSH_CONFIG"
sed -i 's/^#LogLevel.*/LogLevel verbose/'                       "$SSH_CONFIG"
sed -i 's/^#TCPKeepAlive.*/TCPKeepAlive no/'                    "$SSH_CONFIG"
sed -i 's/^#LoginGraceTime.*/LoginGraceTime 20/'                "$SSH_CONFIG"
sed -i 's/^X11Forwarding.*/X11Forwarding no/'                   "$SSH_CONFIG"
sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/'        "$SSH_CONFIG"
sed -i 's/^#PermitTunnel.*/PermitTunnel no/'                    "$SSH_CONFIG"
sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding no/'    "$SSH_CONFIG"
sed -i 's/^#MaxStartups.*/MaxStartups 10:30:100/'               "$SSH_CONFIG"

# Esconder o banner
grep -q "DebianBanner" "$SSH_CONFIG" || echo "DebianBanner no" >> "$SSH_CONFIG"

which ssh-audit || apt-get install -y ssh-audit

ssh-audit -p "$SSH_PORT" localhost

SSH_HARDENIG=$(find /etc/ -iname sshd_config.d)
cat > "$SSH_HARDENIG/90-hardening.conf" << EOF
KexAlgorithms -diffie-hellman-group14-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
Macs -hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,umac-64-etm@openssh.com,umac-64@openssh.com
HostKeyAlgorithms -ecdsa-sha2-nistp256
EOF

systemctl restart ssh && systemctl enable ssh

# Criar usário para acesso exclusivo ao ssh
echo "Deseja cadastrar usuário para acesso ao servidor ssh: S/n: "
read -r ESCOLHA
ESCOLHA=${ESCOLHA:=s}

# Se escolha deiferente de 0, sai do programa
[[ ${ESCOLHA,,} != 's' ]] && { systemctl restart ssh && systemctl enable ssh ; echo "Script finalizado" ; exit 0 ; }

# Adicionar usuário no arquivo ssh
USER_SSH="lc"
grep -q "$USER_SSH" /etc/passwd || { clear ; echo 'Cadastrar novo usário para acessar o ssh' ; useradd "$USER_SSH" && passwd "$USER_SSH" ; }
echo "AllowUsers $USER_SSH" >> "$SSH_CONFIG"
