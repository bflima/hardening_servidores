#!/usr/bin/env/bash

## INFO ##
## NOME.............: conf_banner.sh
## VERSÃO...........: 1.0
## DESCRIÇÃO........: Tunning para kernel com algus ajustes
## DATA DA CRIAÇÃO..: 18/04/2024
## ESCRITO POR......: Bruno Lima
## E-MAIL...........: bruno@lc.tec.br
## DISTRO...........: Debian GNU/Linux 12
## LICENÇA..........: GPLv3
## Git Hub..........: https://github.com/bflima

# Ajustes no Kernel
SYSCTL=$(find /etc/ -iname sysctl.d)

cat > "$SYSCTL/90-tunning.conf" << EOF
### Ajustes no Kernel ###
# Proteção contra IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Proteção contra SYN Floods
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Limitar o número de conexões simultâneas
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 1440000
net.core.somaxconn = 65535

# Reduzir o risco de ataques de ICMP Flood
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Proteção contra ataque de ping da morte
net.ipv4.icmp_echo_ignore_all = 1

# Proteção contra ataque de IP Fragmentado
net.ipv4.ipfrag_high_thresh = 512
net.ipv4.ipfrag_low_thresh = 256

# Aumentar a segurança do TCP/IP Stack# 
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_sack = 0

# Aumentar a segurança do IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Aumentar a eficiência do TCP/IP Stack
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

### KERNEL TUNING ###

# Increase size of file handles and inode cache
fs.file-max = 2097152

# Do less swapping
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2

# Sets the time before the kernel considers migrating a proccess to another core
kernel.sched_migration_cost_ns = 5000000

# Group tasks by TTY
#kernel.sched_autogroup_enabled = 0

### GENERAL NETWORK SECURITY OPTIONS ###

# Number of times SYNACKs for passive TCP connection.
net.ipv4.tcp_synack_retries = 2

# Allowed local port range
net.ipv4.ip_local_port_range = 2000 65535

# Protect Against TCP Time-Wait
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

### TUNING NETWORK PERFORMANCE ###

# Default Socket Receive Buffer
net.core.rmem_default = 31457280

# Maximum Socket Receive Buffer
net.core.rmem_max = 33554432

# Default Socket Send Buffer
net.core.wmem_default = 31457280

# Maximum Socket Send Buffer
net.core.wmem_max = 33554432

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 65536

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 25165824

# Increase the maximum total buffer-space allocatable
# This is measured in units of pages (4096 bytes)
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 65536 131072 262144

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 33554432
net.ipv4.udp_rmem_min = 16384

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 33554432
net.ipv4.udp_wmem_min = 16384

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_tw_reuse = 1
EOF

# Aplicar Hardening
sysctl -p "$SYSCTL"
