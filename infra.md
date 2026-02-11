# Гайд по настройке инфры стенда (Debian-only, Proxmox, VPN, сеть, контейнеры, домен, веб)
*Формат: практичные шаги + чеклисты + команды. Подходит для стенда “1 стенд на команду, 2 участника”, доступ через VPN. Windows отсутствует.*

> ⚠️ Допущения: внутри Proxmox уже есть готовые VM и базовая виртуальная сеть. Твоя задача — **подключиться**, **включить**, **проверить связность**, **развернуть/настроить сервисы** и **зафиксировать конфигурацию**.

---

## Содержание
1. [Подключение к стенду по VPN](#1-подключение-к-стенду-по-vpn)
2. [Proxmox: базовая работа со стендом](#2-proxmox-базовая-работа-со-стендом)
3. [Стартовая проверка сети внутри стенда](#3-стартовая-проверка-сети-внутри-стенда)
4. [Debian-база: пользователи, пакеты, SSH, firewall](#4-debian-база-пользователи-пакеты-ssh-firewall)
5. [Сетевые технологии: маршрутизация, DHCP, DNS, VLAN/NAT](#5-сетевые-технологии-маршрутизация-dhcp-dns-vlannat)
6. [Контейнеризация: Docker/Podman + Compose](#6-контейнеризация-dockerpodman--compose)
7. [Домен без Windows: FreeIPA или Samba AD DC](#7-домен-без-windows-freeipa-или-samba-ad-dc)
8. [Веб-технологии: Nginx/Apache, TLS, reverse proxy](#8-веб-технологии-nginxapache-tls-reverse-proxy)
9. [Набор “боевых” проверок и чеклисты](#9-набор-боевых-проверок-и-чеклисты)
10. [Структура папки конфигов для команды](#10-структура-папки-конфигов-для-команды)

---

## 1) Подключение к стенду по VPN
### 1.1 Что нужно иметь
- VPN-конфиг (`.ovpn` для OpenVPN или конфиги для WireGuard)
- Учётку/сертификаты/ключи
- Адрес панели Proxmox (обычно `https://<ip>:8006`) или jump-host внутри VPN

### 1.2 OpenVPN (Linux)
```bash
sudo apt update
sudo apt install -y openvpn
sudo openvpn --config team.ovpn
```

Проверки:
```bash
ip a
ip r
ping -c 3 <IP_Proxmox_или_jump>
```

### 1.3 WireGuard (Linux)
```bash
sudo apt update
sudo apt install -y wireguard resolvconf
sudo wg-quick up wg0
sudo wg show
```

Проверки:
```bash
ip a
ip r
ping -c 3 <IP_Proxmox_или_jump>
```

### 1.4 Практика команды (2 участника)
- Один человек отвечает за “**сетевой слой**” (VPN, маршруты, DNS).
- Второй — за “**сервисы**” (контейнеры/домен/веб).
- Всё, что меняется, фиксируется в `git` (см. раздел 10).

---

## 2) Proxmox: базовая работа со стендом
### 2.1 Вход
- Открой `https://<proxmox-ip>:8006`
- Логин/пароль от организаторов
- Убедись, что **видишь node**, **storage**, **VM** и **сеть**

### 2.2 Включить VM и проверить консоль
- Запусти нужные VM
- Открой **Console** каждой VM (на случай проблем с сетью/SSH)
- Проверь, что у VM есть IP (через консоль: `ip a`)

### 2.3 Снимки (Snapshots)
Если разрешено:
- Сделай снапшот “clean-start” перед крупными изменениями
- Подпиши: дата/кто/что поменяли

---

## 3) Стартовая проверка сети внутри стенда
Цель: быстро понять **IP-план**, **маршруты**, **DNS**, **сегменты**.

### 3.1 На каждой VM (в консоли/SSH)
```bash
hostnamectl
ip a
ip r
cat /etc/resolv.conf
```

### 3.2 Связность (минимум)
```bash
ping -c 2 <GW_сегмента>
ping -c 2 <DNS_сервера>
ping -c 2 <соседняя_VM_в_сегменте>
```

### 3.3 Проверка DNS
```bash
getent hosts example.local
dig +short example.local
dig +short -x <ip>
```

### 3.4 Быстрый инвентарь “кто где”
На “админской” VM заведи таблицу:
- VM name → IP → роль (dns/dhcp/router/web/db/ipa/…)
- сети (subnet/vlan) → gateway → dhcp? → dns?

---

## 4) Debian-база: пользователи, пакеты, SSH, firewall
### 4.1 Обновления и базовые пакеты
```bash
sudo apt update
sudo apt -y upgrade
sudo apt install -y curl wget git vim tmux htop net-tools tcpdump nmap traceroute dnsutils jq ca-certificates
```

### 4.2 Пользователи и sudo
```bash
sudo adduser <user>
sudo usermod -aG sudo <user>
```

### 4.3 SSH: базовая защита
Файл: `/etc/ssh/sshd_config` (или drop-in в `/etc/ssh/sshd_config.d/`)

Рекомендации:
- выключить логин root по паролю
- включить ключи
- ограничить доступ по пользователям/подсетям (если можно)

```bash
sudo sshd -t
sudo systemctl restart ssh
```

### 4.4 Firewall (UFW или nftables)
**UFW (проще)**
```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

**nftables (более “правильно”)**
```bash
sudo apt install -y nftables
sudo systemctl enable --now nftables
sudo nft list ruleset
```

---

## 5) Сетевые технологии: маршрутизация, DHCP, DNS, VLAN/NAT
### 5.1 Роутинг и форвардинг
Если одна VM играет роль роутера:
```bash
# включить форвардинг
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-forward.conf
sudo sysctl -p /etc/sysctl.d/99-forward.conf
```

NAT (пример, если нужен выход в “наружу” через один интерфейс):
```bash
# nftables пример (концепт): настраивай под свои интерфейсы!
sudo nft add table ip nat
sudo nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
sudo nft add rule ip nat postrouting oifname "eth0" masquerade
```

### 5.2 DHCP (ISC DHCP server или Kea)
**ISC DHCP (часто проще)**
```bash
sudo apt install -y isc-dhcp-server
sudoedit /etc/dhcp/dhcpd.conf
sudoedit /etc/default/isc-dhcp-server
sudo systemctl enable --now isc-dhcp-server
sudo systemctl status isc-dhcp-server
```

### 5.3 DNS (bind9 или unbound + zone)
**bind9 (авторитативный + резолвер)**
```bash
sudo apt install -y bind9 bind9-utils
sudo named-checkconf
sudo systemctl enable --now bind9
sudo systemctl status bind9
```

Проверка:
```bash
dig @<dns-ip> example.local A
dig @<dns-ip> -x <ip>
```

### 5.4 VLAN/bridges в Proxmox (концептуально)
- В Proxmox обычно сеть строится через **Linux Bridge** (`vmbrX`)
- VLAN tagging может быть:
  - на порту VM (tag),
  - или на bridge/physical NIC

Чеклист:
- VM подключена к правильному `vmbr`
- если VLAN — верный `tag`
- шлюз/маска соответствуют сегменту

---

## 6) Контейнеризация: Docker/Podman + Compose
### 6.1 Docker (быстрый старт)
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
docker version
```

Права (без sudo):
```bash
sudo usermod -aG docker $USER
# перелогинься
```

### 6.2 Podman (альтернатива, rootless)
```bash
sudo apt install -y podman podman-compose
podman info
```

### 6.3 Базовый шаблон docker compose (веб + бд)
> Это “инфраструктурный” пример, без эксплойтов и без опасных настроек.

```yaml
# docker-compose.yml
services:
  web:
    image: nginx:stable
    ports:
      - "80:80"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./site:/usr/share/nginx/html:ro
    restart: unless-stopped
```

Запуск:
```bash
docker compose up -d
docker compose ps
docker logs --tail 50 <container>
```

### 6.4 Наблюдаемость контейнеров
```bash
docker stats
docker logs -f <container>
```

---

## 7) Домен без Windows: FreeIPA или Samba AD DC
Так как Windows нет, домен обычно решают одним из вариантов:

### Вариант A — FreeIPA (LDAP + Kerberos + DNS + CA)
**Когда выбирать**: если нужно централизованное управление пользователями/группами, Kerberos SSO, DNS, сертификаты.

Установка (сервер):
```bash
sudo apt update
sudo apt install -y freeipa-server
# затем запускается интерактивный мастер
sudo ipa-server-install
```

Клиент (Debian):
```bash
sudo apt install -y freeipa-client
sudo ipa-client-install
```

Проверки:
```bash
kinit <user>
klist
id <user>
getent passwd <user>
```

### Вариант B — Samba AD DC (AD-подобный домен без Windows)
**Когда выбирать**: если “домен” подразумевает AD-совместимость (LDAP/Kerberos/DNS в стиле AD).

Установка (DC):
```bash
sudo apt update
sudo apt install -y samba krb5-user winbind
# затем provisioning
sudo samba-tool domain provision
sudo systemctl enable --now samba-ad-dc
```

Проверки:
```bash
sudo samba-tool domain info 127.0.0.1
host -t SRV _ldap._tcp.<domain>
```

> Для учебных стендов чаще проще **FreeIPA**. Samba AD DC требует аккуратной DNS/kerberos настройки.

---

## 8) Веб-технологии: Nginx/Apache, TLS, reverse proxy
### 8.1 Nginx базово
```bash
sudo apt update
sudo apt install -y nginx
sudo systemctl enable --now nginx
curl -I http://localhost
```

### 8.2 Reverse proxy на контейнеры/сервисы
Пример server block:
```nginx
server {
  listen 80;
  server_name app.example.local;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### 8.3 TLS (если есть внутренняя CA / FreeIPA CA)
- для внутренних доменов удобно иметь собственную CA (FreeIPA может это дать)
- иначе можно self-signed, но важно раздать доверие клиентам

Проверки:
```bash
openssl s_client -connect app.example.local:443 -servername app.example.local </dev/null | head -n 30
```

### 8.4 Логи веба
```bash
sudo tail -n 50 /var/log/nginx/access.log
sudo tail -n 50 /var/log/nginx/error.log
```

---

## 9) Набор “боевых” проверок и чеклисты
### 9.1 Чеклист “подключились и всё работает”
- [ ] VPN поднят, маршруты корректны (`ip r`)
- [ ] панель Proxmox доступна
- [ ] VM включены, есть IP
- [ ] SSH доступен (где нужно)
- [ ] DNS резолвит внутренние имена
- [ ] между сегментами есть/нет маршрутизации согласно задаче
- [ ] firewall не ломает управление
- [ ] веб доступен из нужных подсетей
- [ ] контейнеры стартуют после ребута

### 9.2 Быстрые сетевые тесты
```bash
# маршруты/трасса
ip r
traceroute -n <target>

# проверка портов (мягко)
nc -vz <host> 80
nc -vz <host> 443
nc -vz <host> 53

# DNS
dig @<dns> app.example.local +short
```

### 9.3 Проверка системных сервисов
```bash
systemctl --failed
journalctl -u <service> --no-pager -n 200
```

### 9.4 Бэкап конфигов (минимум)
```bash
sudo tar -czf /root/config_backup_$(date +%F).tgz \
  /etc /var/lib/dpkg/status /var/log \
  2>/dev/null
```

---

## 10) Структура папки конфигов для команды
Рекомендуется держать всё в git (внутри VPN/в приватном репо, по правилам соревнования/организации).

```text
infra_team/
  README.md
  inventory/
    hosts.md
    ip_plan.md
    services.md
  ansible/                # если разрешено (очень удобно)
  docker/
    compose/
    nginx/
  dns/
    bind/
    zones/
  domain/
    freeipa_notes.md
    samba_notes.md
  web/
    nginx_sites/
  runbooks/
    vpn.md
    proxmox.md
    recovery.md
  evidence/
    commands_log.txt
    screenshots/
```

---

## Мини-runbook “первый час” (суперкратко)
1) VPN up → `ip r` → ping Proxmox  
2) Proxmox: запустить VM → в консоли `ip a`  
3) Составить `inventory/hosts.md` (кто где)  
4) Проверить DNS/маршрутизацию между сегментами  
5) Поднять контейнерный сервис (или веб) → проверить доступность  
6) Настроить минимальный firewall → не сломать SSH/панель  
7) Зафиксировать всё в git + снапшот (если можно)

