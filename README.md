# Домашнее задание № 20 по теме: "Фильтрация трафика - firewalld, iptables". К курсу Administrator Linux. Professional

## Задание

- Реализовать port knocking. centralRouter может попасть на SSH inetRouter через knock скрипт.
- Добавить inetRouter2, который виден (маршрутизируется — host-only тип сети для виртуалки) с хоста или форвардится порт через локалхост.
- Запустить nginx на centralServer.
- Пробросить 80-й порт на inetRouter2 8080.
- Дефолт в инет оставить через inetRouter.
- Реализовать проход на 80-й порт без маскарадинга.

## Выполнение

- ОС: CentOS/8
- Vagrant 2.4.0
- Ansible 2.16.4


config.json:
```json
[
  {
    "name": "inetRouter",
    "cpus": 1,
    "gui": false,
    "box": "centos/8",
    "private_network":
    [
      { "ip": "192.168.255.1", "adapter": 2, "netmask": "255.255.255.252", "virtualbox__intnet": "router-net" },
      { "ip": "192.168.56.10", "adapter": 3, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "centralRouter",
    "cpus": 1,
    "gui": false,
    "box": "centos/8",
    "private_network":
    [
      { "ip": "192.168.255.2", "adapter": 2, "netmask": "255.255.255.252", "virtualbox__intnet": "router-net"      },
      { "ip": "192.168.0.1",   "adapter": 3, "netmask": "255.255.255.240", "virtualbox__intnet": "dir-net"         },
      { "ip": "192.168.0.33",  "adapter": 4, "netmask": "255.255.255.240", "virtualbox__intnet": "hw-net"          },
      { "ip": "192.168.56.11", "adapter": 5, "netmask": "255.255.255.0" }
    ],
    "memory": 640,
    "no_share": true
  },
  {
    "name": "centralServer",
    "cpus": 1,
    "gui": false,
    "box": "centos/8",
    "private_network":
    [
      { "ip": "192.168.0.2",   "adapter": 2, "netmask": "255.255.255.240", "virtualbox__intnet": "dir-net" },
      { "ip": "192.168.56.12", "adapter": 3, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "inetRouter2",
    "cpus": 1,
    "gui": false,
    "box": "centos/8",
    "private_network":
    [
      { "ip": "192.168.0.34", "adapter": 2, "netmask": "255.255.255.240", "virtualbox__intnet": "hw-net" },
      { "ip": "192.168.56.13", "adapter": 3, "netmask": "255.255.255.0" },
      { "ip": "10.10.12.1", "adapter": 4, "netmask": "255.255.255.0", "virtualbox__intnet": "clients-net" }
    ],
    "memory": "640",
    "no_share": true
  }
]
```

Vagrantfile:
```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby : vsa
Vagrant.require_version ">= 2.2.17"

class Hash
  def rekey
  t = self.dup
  self.clear
  t.each_pair{|k, v| self[k.to_sym] = v}
    self
  end
end

require 'json'

f = JSON.parse(File.read(File.join(File.dirname(__FILE__), 'config.json')))
# Локальная переменная PATH_SRC для монтирования
$PathSrc = ENV['PATH_SRC'] || "."

Vagrant.configure(2) do |config|
  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end

  # включить переадресацию агента ssh
  config.ssh.forward_agent = true
  # использовать стандартный для vagrant ключ ssh
  config.ssh.insert_key = false

  last_vm = f[(f.length)-1]['name']

  f.each do |g|

    config.vm.define g['name'] do |s|
      s.vm.box = g['box']
      s.vm.hostname = g['name']

      if g['private_network']
        g['private_network'].each do |ni|
          s.vm.network "private_network", **ni.rekey
        end
      end

      if g['public_network']
        g['public_network'].each do |ni|
          s.vm.network "public_network", **ni.rekey
        end
      end

#      if g['forward_port']
#        s.vm.network 'forwarded_port', guest: g['forward_port'], host: g['forward_port']
#      end

      s.vm.synced_folder $PathSrc, "/vagrant", disabled: g['no_share']

      s.vm.provider :virtualbox do |virtualbox|
        virtualbox.customize [
          "modifyvm",             :id,
          "--audio",              "none",
          "--cpus",               g['cpus'],
          "--memory",             g['memory'],
          "--graphicscontroller", "VMSVGA",
          "--vram",               "64"
        ]

        attachController = false

        if g['disks']
          g['disks'].each do |dname, dconf|
            unless File.exist? (dconf['dfile'])
              attachController = true
              virtualbox.customize [
                'createhd',
                '--filename', dconf['dfile'],
                '--variant',  'Fixed',
                '--size',     dconf['size']
              ]
            end
          end
          if attachController == true
            virtualbox.customize [
              "storagectl", :id,
              "--name",     "SAS Controller",
              "--add",      "sas"
            ]
          end
          g['disks'].each do |dname, dconf|
            virtualbox.customize [
              'storageattach', :id,
              '--storagectl',  'SAS Controller',
              '--port',        dconf['port'],
              '--device',      0,
              '--type',        'hdd',
              '--medium',      dconf['dfile']
            ]
          end
        end
        virtualbox.gui = g['gui']
        virtualbox.name = g['name']
      end
      if g['name'] == last_vm
        s.vm.provision "ansible" do |ansible|
          ansible.playbook = "provisioning/playbook.yml"
          ansible.inventory_path = "provisioning/hosts"
          ansible.host_key_checking = "false"
          ansible.become = "true"
          ansible.limit = "all"
        end
      end
    end
  end
end
```

![Network topology](https://github.com/KasperWPS/lesson30firewall/blob/main/topology.svg)

### Port knocking

Port knocking реализован с использованием nftables для ipv4 и ipv6:
```
table inet filter {

        set clients_ipv4 {
                type ipv4_addr
                flags timeout
        }

        set clients_ipv6 {
                type ipv6_addr
                flags timeout
        }

        set candidates_ipv4 {
                type ipv4_addr . inet_service
                flags timeout
        }

        set candidates_ipv6 {
                type ipv6_addr . inet_service
                flags timeout
        }

        chain portknock {
                type filter hook input priority filter - 10; policy accept;
                iifname "lo" return
                ip saddr != 192.168.255.2 accept
                tcp dport 2425 add @candidates_ipv4 { ip  saddr . 4252 timeout 10s }
                tcp dport 2425 add @candidates_ipv6 { ip6 saddr . 4252 timeout 10s }
                tcp dport 4252 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 { ip  saddr . 1452 timeout 10s }
                tcp dport 4252 ip6 saddr . tcp dport @candidates_ipv6 add @candidates_ipv6 { ip6 saddr . 1452 timeout 10s }
                tcp dport 1452 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 { ip  saddr . 4125 timeout 10s }
                tcp dport 1452 ip6 saddr . tcp dport @candidates_ipv6 add @candidates_ipv6 { ip6 saddr . 4125 timeout 10s }
                tcp dport 4125 ip  saddr . tcp dport @candidates_ipv4 add @clients_ipv4 { ip  saddr timeout 10s } log prefix "Successful portknock: "
                tcp dport 4125 ip6 saddr . tcp dport @candidates_ipv6 add @clients_ipv6 { ip6 saddr timeout 10s } log prefix "Successful portknock: "
                tcp dport { 22 } ip  saddr @clients_ipv4 return
                tcp dport { 22 } ip6 saddr @clients_ipv6 return
                tcp dport { 22 } ct state established,related return
                tcp dport { 22 } counter drop
        }

        chain input {
                type filter hook input priority filter; policy drop;
                ct state invalid counter drop
                ct state established,related accept
                tcp dport 22 ct state new accept
                iif "lo" accept
                icmp type echo-request accept
                udp dport 33434-33524 counter accept comment "for traceroute"
        }
}
table ip nat {
        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip daddr != 192.168.0.0/16 iif "eth1" oif "eth0" masquerade
        }
}
```
Для тестирования, по условиям задания, port knocking работает только для трафика от centralRouter:

- Убедиться, что доступ к 22 порту закрыт
```bash
vagrant ssh centralRouter -c 'ssh vagrant@192.168.255.1'
```
- Запустить скрипт для опроса последовательности портов и попытки устаноления соединения (пароль **vagrant**)
```bash
vagrant ssh centralRouter -c '/usr/local/bin/knock'
```

Листинг скрипта:
```bash
#!/bin/bash

knock() {
  HOST=$1
  shift
  for ARG in "$@"
  do
    nmap -Pn --host-timeout 2 --max-retries 0 -p $ARG $HOST
  done
}

knock 192.168.255.1 2425 4252 1452 4125

ssh vagrant@192.168.255.1
```

### Пробросить порт inetRouter2:8080 на centralServer:80 с установленным nginx:

```
table inet filter {
        chain input {
                type filter hook input priority filter; policy accept;
                ct state invalid counter drop
                iif "lo" accept
                ct state new tcp dport 22 accept
                ct state established,related accept
                ip protocol icmp counter packets 0 bytes 0 accept
                udp dport 33434-33524 counter accept comment "for traceroute"
        }
}
table ip nat {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
                tcp dport 8080 dnat to 192.168.0.2:80
        }

        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                tcp dport 80 ip daddr 192.168.0.2 masquerade
        }
}
```

### Пробросить порт без маскарадинга

- Для проброса порта без маскарадинга необходимо заменить правило в цепочке postrouting таблицы ip nat:
```
tcp dport 80 ip daddr 192.168.0.2 masquerade
```
на:
```
add rule ip nat postrouting ip daddr 192.168.0.2 tcp dport 80 snat to 192.168.0.34
```

- При подобном пробросе в логах web-сервера nginx будет адрес inetRouter2 (192.168.0.34).
- Проброс на порт centralServer:80 без подмены адреса источника невозможен по ряду причин:
  - адрес источника в нашем случае 192.168.56.101. Первый drop будет на хосте centralRouter (функция в ядре ip_rcv_finish) т.к. нет обратного маршрута на принимающем пакет интерфейсе. Настраивается это поведение параметром net.ipv4.conf.all.rp_filter, защита от подмены адресов (спуфинг).
  - Даже если мы доставим пакет на 192.168.0.2, на каждом хосте из нашей схемы присутствует поднятый интерфейс с адресом из подсети 192.168.56.0/24, а в принятом пакете отсутствует обратный маршрут до запросившего установления соединения хоста.
  - В нашей схеме присутствует 2 источника из которых могут поступать пакеты, это inetRouter и inetRouter2, маршрут по-умолчанию через inetRouter

- Чтобы выполнить проброс можно использовать http-proxy реализованный, например, тем же nginx установленным на хосте inetRouter2, тогда в заголовках http (http x-real-ip) к серверу centralServer будут приходить сведения о реальном ip


### Итог

- Knocking port реализован
- Добавлен inetRouter2
  - 192.168.0.34/28 - hw-net
  - 192.168.56.13/24 - hostnetwork
- Установлен nginx на centralRouter
- Проброшен порт centralRouter:80 на inetRouter2:8080
- Дефолт в инет остался через inetRouter
- Проброс порта рассмотрен с маскарадингом (частный случай snat, который подставляет в source address адрес того интерфейса с которого отправляется пакет) и с snat, где адрес отправителя указали вручную
- Разобрали причины по которым, в данном случае, не может быть доставлен пакет до centralServer:80, точнее доставить можно, но смысла в этом мало.
- Для фильтрации использован nftables, т.к. является нативным в CentOS 8




