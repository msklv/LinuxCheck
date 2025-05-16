#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \    Linux Emergency Response/Information Collection     / "
echo " \        Vulnerability Detection Script V3.0             / "
echo " ========================================================= "
echo " # Supports RHEL, Debian, Alt and Astra Linux  system     "
echo " # author: al0ne                                          "
echo " # Original updated on: April 20, 2024                    "
echo " # Adopted on: 3 May 2025 dy msklv                        " 
echo " # References:                                            "
echo " #   1. al0ne https://github.com/al0ne                   "
echo " #   2. Gscan https://github.com/grayddq/GScan            "
echo " #   3. Lynis https://github.com/CISOfy/lynis            "
echo " #   4. container-escape-check                            "
echo " #   5. https://github.com/teamssix/container-escape-check"
echo " ========================================================= "
echo -e "\n"

# Установка пути WEB. Укажите каталог веб-приложения для проверки на наличие Webshell.
webpath='/'

# Адрес для отправки отчета, только с Шифрованием!
#webhook_url='https://localhost:5000/upload'

# Установка пути для сохранения файла
ipaddress=$(ip address | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+(?=\/2)' | head -n 1)
filename=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date +%s)_log'.md'

# Обычное сообщение
print_msg() {
  echo -e "$1\n" | tee -a $filename
}

# Сжатое сообщение, без переноса строки
print_msg_s() {
  echo -e "$1" | tee -a $filename
}

# Блок кода
print_code() {
  echo -e "\`\`\`shell\n$1\n\`\`\`\n" | tee -a $filename
}

reverse_shell_check() {
  echo -e "\n"
  print_code "$(grep -P '(tftp\s\-i|scp\s|sftp\s|bash\s\-i|nc\s\-e|sh\s\-i|wget\s|curl\s|\bexec|/dev/tcp/|/dev/udp/)' $1 $2 $3)"
  print_code "$(grep -P '(useradd|groupadd|chattr|fsockopen|socat|base64|socket|perl|openssl)' $1 $2 $3)"
}

print_msg "# LinuxCheck.sh v3 ru"

### 1. Проверка окружения ###
print_msg "## Environment Check"
# Проверка, запущен ли скрипт с правами root
if [ $UID -ne 0 ]; then
  print_msg "Please run with root privileges!"
  exit 1
else
  print_msg "Currently running with root privileges!"
fi

# Проверка операционной системы: Debian или RHEL
OS='None'

if [ -e "/etc/os-release" ]; then
  source /etc/os-release
  case ${ID} in
  "debian" | "ubuntu" | "devuan" | "astra")
    OS='Debian'
    ;;
  "altlinux" | "alt")
    OS='Alt'
    ;;  
  "centos" | "rhel fedora" | "rhel")
    OS='RHEL'
    ;;
  *) ;;
  esac
fi

if [ $OS = 'None' ]; then
  if command -v apt-get >/dev/null 2>&1; then
    OS='Debian'
  elif command -v yum >/dev/null 2>&1; then
    OS='RHEL'
  else
    echo -e "\nThis system is not fully supported by this script!"
    OS='BaseLinux'
    # echo -e "Exiting"
    # exit 1
  fi
fi


# Выводим тип ОС
print_msg "Detected OS Family: $OS"

# Установка инструментов для анализа сети и отладки
print_msg "Installing network analysis and debugging tools..."
cmdline=(
  "net-tools"   # Лучше заменить на iproute2
  "lsof"
)
for prog in "${cmdline[@]}"; do

  if [ $OS = 'RHEL' ]; then
    soft=$(rpm -q "$prog")
    if echo "$soft" | grep -E 'not installed|not found' >/dev/null 2>&1; then
      echo -e "$prog is being installed......"
      yum install -y "$prog" >/dev/null 2>&1
      yum install -y the_silver_searcher >/dev/null 2>&1
    fi
  elif [ $OS = 'Debian' ]; then
    if  dpkg-query -W -f='${Status}\n' $prog | grep 'install ok installed' >/dev/null 2>&1; then
     echo "$prog is install"
    else
      echo -e "$prog is being installed......"
      apt install -y "$prog" >/dev/null 2>&1
    fi
  elif [ $OS = 'Alt' ]; then
    if rpm -q "$prog" &>/dev/null 2>&1; then
      echo "$prog is install"
    else
      echo -e "$prog is being installed......"
      apt-get install -y $prog >/dev/null 2>&1
    fi

  fi
done

echo -e "\n"

base_check() {
  print_msg "## Basic Configuration Check"
  print_msg "### System Information"
  # Текущий пользователь
  print_msg "* USER: \t\t$(whoami)" 2>/dev/null
  # Версия системы
  print_msg "* Core Version: \t$(uname -r)"
  # Версия дистрибутива
  if [ $OS = 'RHEL' ]; then
    print_msg "* OS Version: \t$(cat /etc/redhat-release | grep -oP '(?<=release )\d+(\.\d+)?')"
  else
    print_msg "* OS Version: \t$(cat /etc/os-release | grep 'VERSION=' | cut -d '=' -f2 | tr -d '"')"
  fi
  # Дата установки
  print_msg "* Install Date: \t$(ls -lct /var/log/installer | awk '{print $6,$7,$8}')"
  # Имя хоста
  print_msg "* Hostname: \t$(hostname -s)"
  # Серийный номер сервера
  print_msg "* Server SN: \t$(dmidecode -t1 | grep -oP '(?<=Serial Number: ).*')"
  #uptime
  print_msg "* Uptime: \t$(uptime | awk -F ',' '{print $1}')"
  # Системная нагрузка
  print_msg "* System Load: \t$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')"
  # Информация о CPU
  print_msg "* CPU info: \t$(grep -oP '(?<=model name\t: ).*' </proc/cpuinfo | head -n 1)"
  # Количество ядер процессора
  print_msg "**CPU Cores:**\t$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)"
  #ipaddress
  ipaddress=$(ifconfig | grep -oP '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | grep -v '127.0.0.1') >/dev/null 2>&1
  print_msg "**IPADDR:**\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta"
  print_msg "**CPU Usage:**  "
  awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
    print_msg_s "$(echo $line | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}')"
  done
  print_msg ""

  # Использование памяти
  print_msg "### Memory Usage"
  print_code "$(free -mh)"

  # Оставшееся пространство
  print_msg "### Remaining Disk Space"
  print_code "$(df -mh)"

  print_msg "### Disk Mounts"
  print_code "$(grep -v '#' </etc/fstab | awk '{print $1,$2,$3}')"

  # Установленное программное обеспечение
  print_msg "### Installed Software"
  cmdline=(
    # Языки программирования
    "which perl"          # Perl
    "which gcc"           # GCC
    "which g++"           # G++
    "which python"        # Python
    "which python3"       # Python 3
    "which php"           # PHP
    "which cc"            # C компилятор
    "which go"            # Go  
    "which node"          # Node.js
    "which nodejs"        # Node.js
    "which npm"           # Node.js пакетный менеджер
    "which yarn"          # Node.js пакетный менеджер
    "which rustc"         # Rust компилятор
    "which cargo"         # Rust пакетный менеджер
    "which dotnet"        # .NET CLI, включая C# компилятор
    "which kotlin"        # Kotlin CLI
    "which swift"         # Swift компилятор
    "which scala"         # Scala компилятор
    "which java"          # Java компилятор
    "which tomcat"        # Tomcat среда выполнения Java
    "which clang"         # Clang компилятор
    "which ruby"          # Ruby интерпретатор
    "which powershell"    # old powershell
    "which pwsh"          # new powershell
    # Инструменты разработки
    "which git"           # Git
    "which code-server"   # VSCode Сервер
    "which vim"           # Vim
    "which ip"            # ip
    "which ansible"       # Ansible
    "which ansible-playbook" # Ansible Playbook
    "which terraform"     # Terraform
    # Серверы
    "which bind"          # BIND DNS
    "which apache"        # Apache
    "which apache2"       # Apache 
    "which nginx"         # Nginx
    "which httpd"         # Apache
    "which docker"        # Docker
    "which docker-compose"  # Docker Compose
    "which tftp"          # TFTP
    "which vsftpd"        # VSFTPD
    "which haproxy"       # HAProxy
    "which envoy"         # Envoy HTTP Proxy
    "which traefik"       # Traefik HTTP Proxy
    "which caddy"         # Caddy HTTP Proxy
    "which varnishd"      # Varnish HTTP Proxy
    "which nomad"         # Nomad
    "which fail2ban"      # Fail2Ban
    "which ufw"           # UFW
    "which ssserver"      # Shadowsocks VPN
    "which openvpn"       # OpenVPN
    # БД и кластеры
    "which mysql"         # MySQL
    "which psql"          # PostgreSQL
    "which redis-cli"     # Redis
    "which redis"         # Redis
    "which mongodb"       # MongoDB
    "which kafka"         # Kafka
    "which etcd"          # etcd
    "which elasticsearch" # Elasticsearch
    "which consul"        # Consul
    "which zookeeper"     # Zookeeper
    "which influxd"       # InfluxDB
    "which clickhouse"    # ClickHouse
    "which couchdb"       # CouchDB
    "which cassandra"     # Cassandra
    "which scylladb"      # ScyllaDB
    "which neo4j"         # Neo4j
    "which arangod"       # ArangoDB
    "which dgraph"        # Dgraph
    "which rqlite"        # Rqlite
    "which leveldb"       # LevelDB
    "which rocksdb"       # RocksDB
    "which vault"         # Vault
    "which rabbitmqctl"   # RabbitMQ
    "which redpanda"      # Redpanda
    # Kubernetes
    "which kubectl"       # kubectl
    "which kubeadm"       # kubeadm
    "which kubelet"       # kubelet
    "which kube-proxy"    # kube-proxy
    "which helm"          # Helm
    "which minikube"      # Minikube
    "which k3s"           # K3s
    "which kind"          # Kind
    "which crictl"        # crictl
    "which ctr"           # ctr
    "which nerdctl"       # nerdctl
    "which oc"            # oc
    "which istioctl"      # istioctl
  )
  summary=""
  for which in "${cmdline[@]}"; do
    # Запоминаем результат выполнения команды
    result=$(eval "$which")
    # Проверяем, была ли команда найдена
    if [ $? -eq 0 ]; then
      # Если команда найдена, выводим ее путь
      summary+="$which is installed at: $result"$'\n'
    else
      # Если команда не найдена, выводим сообщение
      summary+="$which is not installed"$'\n'
    fi
  done
  # Выводим список установленных программ
  print_code "$summary"
  

  #HOSTS
  print_msg "### /etc/hosts"
  print_code "$(cat /etc/hosts | egrep -v "#")"
}

process_check() {
  print_msg "## Process Information Check"

  print_msg "### CPU Usage TOP 15"
  cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
  print_code "${cpu}"

  print_msg "### Memory Usage TOP 15"
  mem=$(ps aux | grep -v ^'USER' | sort -rn -k4 | head -15) 2>/dev/null
  print_code "${mem}"

  print_msg "### Processes with Parent Process ID 1"
  print_code "$(ps -e -o user,pid,ppid,cmd | awk '$3 == 1' | egrep -v "containerd-shim|/lib/systemd/systemd|/usr/sbin/cron|dbus|rsyslogd|containerd|/usr/sbin/sshd|/usr/bin/dockerd|/usr/sbin/arpd|/bin/login|/usr/sbin/vnstatd")"

  print_msg "### Bash reverse shell processes"
  tcp_reverse=$(ps -ef | grep -P 'sh -i' | egrep -v 'grep' | awk '{print $2}' | xargs -i{} lsof -p {} | grep 'ESTAB')
  if [ -n $tcp_reverse ]; then
    print_code "$tcp_reverse"
  else
    print_code "No bash -i reverse shell detected!"
  fi
  print_msg "### SSH symbolic link backdoor processes"
  if ps -ef | grep -P '\s+\-oport=\d+' >/dev/null 2>&1; then
    print_msg "$(ps -ef | grep -P '\s+\-oport=\d+')"
  else
    print_msg "No SSH symbolic link backdoor detected"

  fi
}

network_check() {
  print_msg "## Network/Traffic Check"
  #ifconfig
  print_msg '### ifconfig'
  print_code "$(/sbin/ifconfig -a)"

  # Сетевой трафик
  print_msg "### Network Traffic"
  print_msg "**Interface**    **ByteRec**   **PackRec**   **ByteTran**   **PackTran**"
  awk ' NR>2' /proc/net/dev | while read line; do
    print_msg_s "$line" | awk -F ':' '{print "  "$1"  " $2}' | awk '{print $1"   "$2 "    "$3"   "$10"  "$11}'
  done
  print_msg ""

  # Мониторинг портов
  print_msg "### Port Listening"
  print_code "$(netstat -tulpen | grep -P 'tcp|udp.*')"

  # Внешне открытые порты
  print_msg "### External Open Ports"
  print_code "$(netstat -tulpen | awk '{print $1,$4}' | grep -P -o '.*0.0.0.0:(\d+)|:::\d+')"

  # Сетевые подключения
  print_msg "### Network Connections"
  print_msg "**TCP Connections**"
  print_code "$(netstat -antop | grep -P ESTAB)"
  print_msg "**UDP Connections**"
  print_code "$(netstat -anp | grep -P udp)"

  # Состояния TCP соединений
  print_msg "### TCP Connection States"
  print_code "$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')"

  # Таблица маршрутов
  print_msg "### Route Table"
  print_code "$(/sbin/route -nee)"

  # Маршрутизация включена
  print_msg "### IP Forwarding"
  ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
  if [ -n "$ip_forward" ]; then
    print_code "/proc/sys/net/ipv4/ip_forward is enabled!"
  else
    print_code "IP forwarding is not enabled on this server!"
  fi

  #DNS
  print_msg "### DNS Server"
  print_code "$(grep -oP '\d+\.\d+\.\d+\.\d+' </etc/resolv.conf)"

  #ARP
  print_msg "### ARP"
  print_code "$(arp -n -a)"

  # Промискуитетный режим
  print_msg "### Promiscuous Mode"
  if ip link | grep -P PROMISC >/dev/null 2>&1; then
    print_code "Promiscuous mode detected!"
  else
    print_code "No promiscuous mode detected!"

  fi

  # Брандмауэр
  print_msg "### IPTABLES Firewall"
  print_code "$(iptables -L)"

}

crontab_check() {
  print_msg "## Crontab Check"

  #crontab
  print_msg "### Crontab Files"
  print_msg "crontab -l"
  print_code "$(crontab -u root -l | egrep -v '#')"
  print_msg "ls -alht /etc/cron.*/*"
  print_code "$(ls -alht /etc/cron.*/*)"

  # crontab Содержимое
  print_msg "### Crontab File Contents"
  print_code "$(find /var/spool/cron/ -type f -print0 | xargs -0 sudo cat | egrep -v '#')"

  # Подозрительные команды в crontab
  print_msg "### Crontab Backdoor"
  reverse_shell_check /etc/cron*
  reverse_shell_check /var/spool/cron/*
}

env_check() {
  print_msg "## Environment Variables Check"
  #env
  print_msg "### env"
  print_code "$(env)"

  #PATH
  print_msg "### PATH"
  print_code "$PATH"

  print_msg "### Linux Dynamic Linker Variables"

  #LD_PRELOAD
  if [[ -n $LD_PRELOAD ]]; then
    print_msg "**LD_PRELOAD**"
    print_code $LD_PRELOAD
  fi
  #LD_ELF_PRELOAD
  if [[ -n $LD_ELF_PRELOAD ]]; then
    print_msg "**LD_ELF_PRELOAD**"
    print_code $LD_ELF_PRELOAD
  fi
  #LD_AOUT_PRELOAD
  if [[ -n $LD_AOUT_PRELOAD ]]; then
    print_msg "**LD_AOUT_PRELOAD**"
    print_code $LD_AOUT_PRELOAD
  fi
  #PROMPT_COMMAND
  if [[ -n $PROMPT_COMMAND ]]; then
    print_msg "**PROMPT_COMMAND**"
    print_code $PROMPT_COMMAND
  fi
  #LD_LIBRARY_PATH
  if [[ -n $LD_LIBRARY_PATH ]]; then
    print_msg "**LD_LIBRARY_PATH**"
    print_code $LD_LIBRARY_PATH
  fi
  #ld.so.preload
  preload='/etc/ld.so.preload'
  if [ -e "${preload}" ]; then
    print_msg "**ld.so.preload**"
    print_code ${preload}
  fi
  # Переменные окружения запущенных процессов
  print_msg "### Running Process Environment Variables"
  print_code "$(grep -P 'LD_PRELOAD|LD_ELF_PRELOAD|LD_AOUT_PRELOAD|PROMPT_COMMAND|LD_LIBRARY_PATH' /proc/*/environ)"
}

user_check() {
  print_msg "## User Information Check"

  print_msg "### Loginable Users"
  print_code "$(cat /etc/passwd | egrep -v 'nologin$|false$')"

  print_msg "### Root Privilege (Non-root) Accounts"
  print_code "$(cat /etc/passwd | awk -F ':' '$3==0' | egrep -v root:)"

  print_msg "### /etc/passwd File Modification Date: "

  print_code "$(stat /etc/passwd | grep -P -o '(?<=Modify: ).*')"

  print_msg "### sudoers (Pay attention to NOPASSWD)"
  print_code "$(cat /etc/sudoers | egrep -v '#' | sed -e '/^$/d' | grep -P ALL)"

  print_msg "### Login Information w"
  print_code "$(w)"
  print_msg "### Login Information last"
  print_code "$(last)"
  print_msg "### Login Information lastlog"
  print_code "$(lastlog)"

  print_msg "### Login IPs"
  print_code "$(grep -i -a Accepted /var/log/secure /var/log/auth.* 2>/dev/null | grep -Po '\d+\.\d+\.\d+\.\d+' | sort | uniq)"

}

init_check() {
  print_msg "## Linux Startup Items Check"

  print_msg "### /etc/init.d Records"
  print_code "$(ls -alhtR /etc/init.d | head -n 30)"
  print_msg "### /etc/init.d Black Characteristics"
  reverse_shell_check /etc/init.d/*
}

service_check() {

  print_msg "## Service Status Check"

  print_msg "### Running Services "
  print_code "$(systemctl -l | grep running | awk '{print $1}')"

  print_msg "### Recently Added Services "
  print_code "$(ls -alhtR /etc/systemd/system/multi-user.target.wants)"
  print_code "$(ls -alht /etc/systemd/system/*.service | egrep -v 'dbus-org')"

}

bash_check() {

  print_msg -e "## Bash Configuration Check"
  #Просмотр файла history
  print_msg "### History Files"
  print_code "$(ls -alht /root/.*_history)"

  print_msg "### Sensitive Operations in History"
  print_code "$(cat ~/.*history | grep -P '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b|mysql\b|mysqldump' | egrep -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b')"

  #/etc/profile
  print_msg "### /etc/profile "
  print_code "$(cat /etc/profile | egrep -v '#')"

  # $HOME/.profile
  print_msg "### .profile "
  print_code "$(cat $HOME/.profile | egrep -v '#')"

  #/etc/rc.local
  print_msg "### /etc/rc.local "
  print_code "$(cat /etc/rc.local | egrep -v '#')"

  #~/.bash_profile
  print_msg "### ~/.bash_profile "
  if [ -e "$HOME/.bash_profile" ]; then
    print_code "$(cat ~/.bash_profile | egrep -v '#')"
  fi

  #~/.bashrc
  print_msg "### ~/.bashrc "
  print_code "$(cat ~/.bashrc | egrep -v '#' | sort | uniq)"

  #~/.bashrc
  print_msg "### ~/.zshrc "
  print_code "$(cat ~/.zshrc | egrep -v '#' | sort | uniq)"

}

file_check() {
  print_msg "## File Check"
  print_msg "System File Modification Time "
  cmdline=(
    "/sbin/ifconfig"
    "/bin/ls"
    "/bin/login"
    "/bin/netstat"
    "/bin/top"
    "/bin/ps"
    "/bin/find"
    "/bin/grep"
    "/etc/passwd"
    "/etc/shadow"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/root/.ssh/authorized_keys"
    "/etc/hosts"
    "/etc/resolv.conf"
  )
  for soft in "${cmdline[@]}"; do
    print_msg_s "File: $soft\t\t\tModification Date: $(stat $soft | grep -P -o '(?<=Modify: )[\d-\s:]+')"
  done
  print_msg ""

  print_msg "### Hidden Files"
  print_msg "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*.")"

  #tmp каталог
  print_msg "### /tmp"
  print_code "$(ls /tmp /var/tmp /dev/shm -alht)"

  #alias
  print_msg "### alias"
  print_code "$(alias | egrep -v 'git')"

  #SUID
  print_msg "### SUID"
  print_code "$(find / ! -path "/proc/*" -perm -004000 -type f | egrep -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps')"

  #lsof -L1, процесс существует, но файл был удален
  print_msg "### lsof +L1"
  print_code "$(lsof +L1)"

  # Изменения за последние 7 дней (mtime)
  print_msg "### Last Seven Days File Changes (mtime) "
  print_code "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"

  # Изменения за последние 7 дней (ctime)
  print_msg "### Last Seven Days File Changes (ctime) "
  print_code "$(find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | egrep -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {})"

  # Большие файлы >200MB
  # Некоторые хакеры могут упаковать базу данных или сайт в один файл и скачать его
  print_msg "### Large Files >200MB "
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | grep -P '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' | egrep -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1|overlay2')"

  # Чувствительные файлы
  print_msg "### Sensitive Files "
  print_code "$(find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | egrep -v '/lib/python' | xargs -i{} ls -alh {})"

  print_msg "### Suspicious Hacker Files "
  print_code "$(find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | egrep -v '/pkgs/|/envs/|overlay2')"

}

rootkit_check() {
  print_msg "## Rootkit Check"
  #lsmod Подозрительные модули
  print_msg "### lsmod Suspicious Modules"
  print_code "$(lsmod | egrep -v 'ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|ip6table_raw|skx_edac|intel_rapl|wmi|acpi_pad|ast|i40e|ptp|nfit|libnvdimm|bpfilter|failover|toa|tls|nft_|qemu_fw_cfg')"

  print_msg "### Rootkit Kernel Modules"
  kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
  if [ -n "$kernel" ]; then
    print_msg "Kernel sensitive functions detected! Suspected Rootkit kernel module"
    print_msg "$kernel"
  else
    print_msg "No kernel sensitive functions found"
  fi

  print_msg "### Suspicious .ko Modules"
  print_code "$(find / ! -path '/var/lib/docker/overlay2/*' ! -path '/proc/*' ! -path '/usr/lib/modules/*' ! -path '/lib/modules/*' ! -path '/boot/*' -regextype posix-extended -regex '.*\.ko' | egrep -v 'tutor.ko')"

}

ssh_check() {
  print_msg "## SSH Check"
  #IP-адреса, осуществляющие brute-force SSH
  print_msg "### SSH Brute-force IPs"
  if [ $OS = 'RHEL' ]; then
    print_code "$(grep -P -i -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | grep -P '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25)"
  elif [ $OS = 'Debian' ]; then
    print_code "$(grep -P -i -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | grep -P '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25)"
  elif [ $OS = 'Alt' ]; then
    print_code "$(journalctl -n 1000 | grep -P -i 'Failed password' | awk '{print $12}' | grep -P '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25)"  # AltLinux 
  fi

  #SSHD
  print_msg "### SSHD"
  print_msg "/usr/sbin/sshd"
  print_code "$(stat /usr/sbin/sshd | grep -P 'Access|Modify|Change')"

  # Проверка конфигурации SSH на бэкдор
  print_msg "### SSH Backdoor Configuration"
  if [ -e "$HOME/.ssh/config" ]; then
    print_msg "$(grep LocalCommand <~/.ssh/config)"
    print_msg "$(grep ProxyCommand <~/.ssh/config)"
  else
    print_msg "No ssh configuration file found"
  fi

  # Проверка PAM на бэкдор
  print_msg "### PAM Backdoor Detection "
  ls -la /usr/lib/security 2>/dev/null
  ls -la /usr/lib64/security 2>/dev/null

  print_msg "### SSH inetd Backdoor Detection "
  if [ -e "/etc/inetd.conf" ]; then
    grep -E '(bash -i)' </etc/inetd.conf
  fi

  print_msg "### SSH key"
  user_dirs=$(ls /home)
  for user_dir in $user_dirs; do
    sshkey="/home/${user_dir}/.ssh/authorized_keys"

    if [ -s "${sshkey}" ]; then
      print_msg "User: ${user_dir}\n"
      print_code "$(cat ${sshkey})"
    fi
  done

  # Проверка файла authorized_keys в каталоге /root
  print_msg "### authorized_keys"
  root_sshkey="/root/.ssh/authorized_keys"

  if [ -s "${root_sshkey}" ]; then
    print_code "$(cat ${root_sshkey})"
  else
    print_code "User: root - SSH key file does not exist"
  fi
}

webshell_check() {

  print_msg "## Webshell Check"

  print_msg "### PHP Webshell Detection"
  print_code "$(grep -P -i -r -l 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'getruntime|processimpl|processbuilder|defineclass|classloader|naming.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\u0063\\u006c\\u0061\\u0073\\u0073' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'phpinfo|move_uploaded_file|system|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|ob_start' $webpath --include='*.php*' --include='*.phtml')"
  print_code "$(grep -P -i -r -l 'array_map|uasort|uksort|array_diff_uassoc|array_diff_ukey|array_intersect_uassoc|array_intersect_ukey|array_reduce|array_filter|array_udiff|array_udiff_assoc|array_udiff_uassoc|array_uintersect|array_uintersect_assoc|array_uintersect_uassoc|array_walk|array_walk_recursive|register_shutdown_function|register_tick_function|filter_var_array|yaml_parse|sqlite_create_function|fgetc|fgets|fgetss|fpassthru|fread|file_get_contents|readfile|stream_get_contents|stream_get_line|highlight_file|show_source|file_put_contents|pfsockopen|fsockopen' $webpath --include='*.php*' --include='*.phtml')"

  #JSP Webshell Detection
  print_msg "### JSP Webshell Detection"
  print_code "$(grep -P -i -r -l '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath --include='*.jsp*' --include='*.jhtml')"

}

poison_check() {

  print_msg "## Supply Chain Poisoning Detection"

  print_msg "### Python2 pip Detection"
  print_code "$(pip freeze | grep -P 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol')"

  print_msg "### Python3 pip Detection"
  print_code "$(pip3 freeze | grep -P 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol')"

}

miner_check() {

  print_msg "## Mining Trojan Detection"

  print_msg "### Common Mining Process Detection"
  print_code "$(ps aux | grep -P "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb|i2pd" | egrep -v 'grep')"
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f)"

  print_msg "### Ntpclient Mining Trojan Detection"
  print_code "$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz')"
  print_code "$(ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)"

  print_msg "### WorkMiner Mining Trojan Detection"
  print_code "$(ps aux | grep -P "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | egrep -v 'grep')"
  print_code "$(ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)"

}

risk_check() {

  print_msg "## Server Risk/Vulnerability Check"

  print_msg "### Redis Weak Password Detection"
  print_code "$(cat /etc/redis/redis.conf 2>/dev/null | grep -P '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)')"

  print_msg "### JDWP Debugging Detection"
  if ps aux | grep -P '(?:runjdwp|agentlib:jdwp)' | egrep -v 'grep' >/dev/null 2>&1; then
    print_code "JDWP debugging high-risk process detected\n $(ps aux | grep -P '(?:runjdwp|agentlib:jdwp)' | egrep -v 'grep') "
  fi

  print_msg "### Python http.server Directory Listing Detection"
  print_code "$(ps aux | grep -P http.server | egrep -v 'grep')"
}

docker_check() {

  print_msg "## Docker Information Check"

  print_msg "### Running Docker Images"
  print_code "$(docker ps)"

  print_msg "### CAP_SYS_ADMIN Privilege Detection"
  if command -v capsh >/dev/null 2>&1; then
    cap_sys_adminNum=$(capsh --print | grep cap_sys_admin | wc -l)
    if [ $cap_sys_adminNum -gt 0 ]; then
      print_code "CAP_SYS_ADMIN privilege detected!"
    fi
  else
    print_code "capsh command not found!"
  fi

  print_msg "### CAP_DAC_READ_SEARCH Privilege Detection"
  if command -v capsh >/dev/null 2>&1; then
    cap_dac_read_searchNum=$(capsh --print | grep cap_dac_read_search | wc -l)
    if [ $cap_dac_read_searchNum -gt 0 ]; then
      print_code "CAP_DAC_READ_SEARCH privilege detected!"
    fi
  else
    print_code "capsh command not found!"
  fi
}

#upload_report() {

  # Загрузка на указанный интерфейс
#  if [[ -n $webhook_url ]]; then
#    curl -X POST -F "file=@$filename" "$webhook_url"
#  fi

#}

# Проверка базовой информации о сервере
base_check
# Проверка информации о процессах (использование CPU/памяти, проверка на наличие бэкдоров)
process_check
# Проверка сети
network_check
# Проверка планировщика задач
crontab_check
# Проверка переменных окружения
env_check
# Проверка файлов пользователей
user_check
# Проверка автозагрузки
init_check
# Проверка служб
service_check
# Проверка bash
bash_check
# Проверка файлов на наличие хакерских/бэкдор файлов
file_check
# Проверка rootkit
rootkit_check
# Проверка SSH
ssh_check
# Проверка webshell
webshell_check
# Проверка цепочки поставок
poison_check
# Проверка на наличие майнинговых программ
miner_check
# Проверка рисков сервера
risk_check
# Проверка Docker
docker_check
# Загрузка отчета
#upload_report
