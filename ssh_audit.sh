#!/usr/bin/env/bash

## INFO ##
## NOME.............: ssh_audit.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Hardening no arquivo ssh, permitindo acesso somente ao usuário cadastrado,
## cifras ajustadas no arquivo de configuração, site usasdo para testes https://www.sshaudit.com/
## DATA DA CRIAÇÃO..: 05/08/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3
## Git Hub..........: https://github.com/bflima
## Referência.......: https://wiki.archlinux.org/title/Sshguard

# Atualizar sistema
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y

# Pacotes necessários
PACOTES=(iptables netfilter-persistent iptables-persistent sshguard ssh-audit bash-completion)
for item in "${PACOTES[@]}" ; do { command -v "$item" || apt install -qy "$item" ; } ; done 
unset DEBIAN_FRONTEND

systemctl start sshguard && systemctl enable sshguard

SSHGUARD_CONFIG=$(find /etc -iname sshguard.conf)
cp "$SSHGUARD_CONFIG"{,.bak}

SSHGUARD_IPT=$(find /usr/ -iname \*fw-iptables)

cat > "$SSHGUARD_CONFIG" << EOF
BACKEND="$SSHGUARD_IPT"
LOGREADER="LANG=C journalctl -afb -p info -n1 -t sshd -o cat"
THRESHOLD=40
BLOCK_TIME=240
DETECTION_TIME=3600
WHITELIST_FILE=/etc/sshguard/whitelist
BLACKLIST_FILE=50:/etc/sshguard/blacklist
EOF

# Criar regras iptables
iptables -nL sshguard           || iptables -N sshguard
iptables -C INPUT -j sshguard   || iptables -A INPUT -j sshguard
# Regra para bloqueio das portas
iptables -C INPUT -m multiport -p tcp --destination-ports 22,110,143 -j sshguard || \
iptables -A INPUT -m multiport -p tcp --destination-ports 22,110,143 -j sshguard

# Salvar regras
iptables-save > /etc/iptables/iptables.rules
service netfilter-persistent save

systemctl restart sshguard


# Hardening seguindo as práticas do site oficial https://www.ssh-audit.com/hardening_guides.html#debian_12
rm -rf /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli

SSH_HARDENIG=$(find /etc/ -iname sshd_config.d)

cat > "$SSH_HARDENIG/90-hardening.conf" << EOF
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

RequiredRSASize 3072

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
EOF

systemctl restart ssh

iptables  -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --set || \
iptables  -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set

iptables  -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP || \
iptables  -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP

ip6tables -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --set || \
ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set

ip6tables -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP || \
ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP

service netfilter-persistent save

ssh-audit -p 22 localhost

# Ajustar arquivo de auditoria
dpkg-query -s auditd || apt install -y auditd audispd-plugins
systemctl enable auditd
systemctl start auditd

# Ajustando arquivos de log
systemctl status systemd-journald | grep -qi active || exit 10

J_LOG=$(find /etc -type f -iname journald.conf)

grep -i '.*SystemMaxUse'    "$J_LOG" && { sed -i 's/.*SystemMaxUse.*/SystemMaxUse=1G/g'         "$J_LOG" ; }
grep -i '.*SystemKeepFree'  "$J_LOG" && { sed -i 's/.*SystemKeepFree.*/SystemKeepFree=500M/g'   "$J_LOG" ; }
grep -i '.*RuntimeMaxUse'   "$J_LOG" && { sed -i 's/.*RuntimeMaxUse.*/RuntimeMaxUse=200M/g'     "$J_LOG" ; }
grep -i '.*RuntimeKeepFree' "$J_LOG" && { sed -i 's/.*RuntimeKeepFree.*/RuntimeKeepFree=50M/g'  "$J_LOG" ; }
grep -i '.*MaxFileSec'      "$J_LOG" && { sed -i 's/.*MaxFileSec.*/MaxFileSec=1month/g'         "$J_LOG" ; }

systemctl restart systemd-journald.service

# Instalar auditd
command -v auditd || apt install -y auditd
systemctl start auditd 
systemctl enable auditd

# Regras de auditoria
RULES_DIR=$(find /etc -type d -iname 'rules.d' | grep audit)

[[ -d "$RULES_DIR" ]] || mkdir -p /etc/audit/rules.d/ 

RULES_AUD=$(find "$RULES_DIR" -type f -iname audit.rules)

tee "$RULES_AUD" > /dev/null << 'EOF'
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1

## Regras Adicionadas
## Diretorio /etc 
-w /etc/ -p wa -k config_changes
## Boot
-w /boot/grub/grub.cfg   -p wa -k grub_changes
## SSH
-w /etc/ssh/sshd_config -p rwxa -k sshd_config
## Cron
-w /etc/crontab -p wa -k crontab_changes
-w /etc/cron.d/ -p wa -k cron_d_changes
## Log
-w /var/run/utmp -p wa -k utmp_changes
-w /var/run/wtmp -p wa -k wtmp_changes
## Senhas
-w /etc/passwd  -p wa -k passwd_changes
-w /etc/shadow  -p wa -k shadow_changes
-w /etc/group   -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
## Log
-w /var/log/auth.log    -p rwxa -k auth_log
-w /var/log/syslog      -p rwxa -k syslog_changes
-w /var/log/lastlog     -p wa -k lastlog_changes
-w /var/log/faillog     -p wa -k faillog_changes
## Serviços
-a always,exit -F arch=b64 -S execve    -k exec_commands
-a always,exit -F arch=b32 -S execve    -k exec_commands
-a always,exit -F arch=b64 -S systemctl -k service_changes
-a always,exit -F arch=b32 -S systemctl -k service_changes
-a always,exit -F arch=b64 -S socket,bind,connect -k network_changes
-a always,exit -F arch=b32 -S socket,bind,connect -k network_changes
EOF

systemctl restart auditd
