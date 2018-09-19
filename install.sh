#!/usr/bin/env bash

if readlink /proc/$$/exe | grep -q "dash"; then
  e cho "This script needs to be run with bash, not sh"
  exit
fi

if [[ "$E UID" -ne 0  ]]; then
  echo "Sorry, you need to run this as root"
  exit
  f   i

  if [[ ! -e /dev/net/tun  ]]; then
    echo "The TUN device is not availa  ble
    You need to enable TUN before running this script"
    exit
  fi

  if [[   -e /etc/debian_version  ]]; then
    OS=debian
    GROUPNAME=nogroup
    RCLOCAL=      '/etc/rc.local'
  elif [[ -e /etc/centos-release || -e /etc/redhat-release  ]]; then
    OS=centos
    GROUPNAME=nobody
    RCLOCAL='/etc/rc.d/rc.local'
  else
    echo "Looks like you aren't running this installer on Debian, Ubuntu  or CentOS"
    exit
  fi

  newclient () {
    # Generates the custom client.ovpn
    cp /etc/openvpn/client-common.txt ~/$1.ovpn
    echo "<ca>" >> ~/$1.ovpn
    cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
    echo "</ca>" >> ~/    $1.ovpn
    echo "<cert>" >> ~/$1.ovpn
    cat /etc/openvpn/easy-rsa/pki/issu    ed/$1.crt >> ~/$1.ovpn
    echo "</cert>" >> ~/$1.ovpn
    echo "<key>" >> ~/    $1.ovpn
    cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
    ech   o "</key>" >> ~/$1.ovpn
    echo "<tls-auth>" >> ~/$1.ovpn
    cat /etc/openv    pn/ta.key >> ~/$1.ovpn
    echo "</tls-auth>" >> ~/$1.ovpn

  }

  if [[ -e /et  c/openvpn/server.conf  ]]; then
    while :
    do
      clear
      echo "Looks like O          penVPN is already installed."
      echo
      echo "What do you want to do?"
                echo "   1) Add a new user"
                echo "   2) Revoke an existing user"
                e         cho "   3) Remove OpenVPN"
                echo "   4) Exit"
                read -p "Select an opt        ion [1-4]: " option
                case $option in
                  1)
                    echo
                    echo "Tell me a                      name for the client certificate."
                    echo "Please, use one word only,      no special characters."
                    read -p "Client name: " -e CLIENT
                    cd /etc           /openvpn/easy-rsa/
                    ./easyrsa build-client-full $CLIENT nopass
                    # G           enerates the custom client.ovpn
                    newclient "$CLIENT"
                    echo
                    echo                  "Client $CLIENT added, configuration is available at:" ~/"$CLIENT.ovpn"
                    exit
                    ;;
                  2)
                    # This option could be documented a bit better and                        maybe even be simplified
                    # ...but what can I say, I want some sleep      too
                    NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt       | grep -c "^V")
                    if [[ "$NUMBEROFCLIENTS" = '0'  ]]; then
                      echo
                                        echo "You have no existing clients!"
                                        exit
                                      fi
                                      echo
                                      echo "                              Select the existing client certificate you want to revoke:"
                                      tail -n       +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                                      if [[ "$NUMBEROFCLIENTS" = '1'  ]]; then
                                        read -p "Select               one client [1]: " CLIENTNUMBER
                                      else
                                        read -p "Select one client [              1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
                                      fi
                                      CLIENT=$(tail -n +2 /etc/o            penvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
                                      echo
                                      read -p "Do you really want to revoke access for clien            t $CLIENT? [y/N]: " -e REVOKE
                                      if [[ "$REVOKE" = 'y' || "$REVOKE" = '      Y'  ]]; then
                                        cd /etc/openvpn/easy-rsa/
                                        ./easyrsa --batch revoke                $CLIENT
                                        EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
                                        rm -f pki/reqs/               $CLIENT.req
                                        rm -f pki/private/$CLIENT.key
                                        rm -f pki/issued/$CLI               ENT.crt
                                        rm -f /etc/openvpn/crl.pem
                                        cp /etc/openvpn/easy-rsa/pki                /crl.pem /etc/openvpn/crl.pem
                                        # CRL is read with each client connec       tion, when OpenVPN is dropped to nobody
                                        chown nobody:$GROUPNAME /et       c/openvpn/crl.pem
                                        echo
                                        echo "Certificate for client $CLIENT rev                oked!"
                                      else
                                        echo
                                        echo "Certificate revocation for client $CL                     IENT aborted!"
                                      fi
                                      exit
                                      ;;
                                    3)
                                      echo
                                      read -p "Do you re                                    ally want to remove OpenVPN? [y/N]: " -e REMOVE
                                      if [[ "$REMOVE" = 'y      ' || "$REMOVE" = 'Y'  ]]; then
                                        PORT=$(grep '^port ' /etc/openvpn/ser       ver.conf | cut -d " " -f 2)
                                        PROTOCOL=$(grep '^proto ' /etc/openvpn/       server.conf | cut -d " " -f 2)
                                        if pgrep firewalld; then
                                          IP=$(f                  irewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
                                          #          Using both permanent and not permanent rules to avoid a firewalld reload.
                                          firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
                                          f                   irewall-cmd --zone=trusted --remove-source=10.8.0.0/24
                                          firewall-cm         d --permanent --zone=public --remove-port=$PORT/$PROTOCOL
                                          firewall          -cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
                                          firewa          ll-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                          firewall-cmd --permanent --direct --re          move-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                        else
                                          IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -                  d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
                                          iptables           -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                          sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0         \/24 -j SNAT --to /d' $RCLOCAL
                                          if iptables -L -n | grep -qE '^ACCE         PT'; then
                                            iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
                                                        iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
                                                        iptables -D FO                        RWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
                                                        sed -i "/ipt            ables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
                                                        s           ed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
                                                                  sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j A  CCEPT/d" $RCLOCAL
                                                                fi
                                                              fi
                                                              if sestatus 2>/dev/null | grep "Cu                          rrent mode" | grep -q "enforcing" && [[ "$PORT" != '1194'  ]]; then
                                                                        semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
                                                                      fi
                                                                      if [[                  "$OS" = 'debian' ]]; then
                                                                        apt-get remove --purge -y openvpn
                                                                        e                 lse
                                                                        yum remove openvpn -y
                                                                      fi
                                                                      rm -rf /etc/openvpn
                                                                      rm -f                                  /etc/sysctl.d/30-openvpn-forward.conf
                                                                      echo
                                                                      echo "OpenVPN remov               ed!"
                                                                    else
                                                                      echo
                                                                      echo "Removal aborted!"
                                                                    fi
                                                                    exit
                                                                    ;;
                                                                                                              4) exit;;
                                                                                                            esac
                                                                                                          done
                                                                                                        else
                                                                                                          clear
                                                                                                          echo 'Welcome to this OpenVPN "ro             ad warrior" installer!'
                                                                                                          echo
                                                                                                          # OpenVPN setup and first user creation
                                                                                                              echo "I need to ask you a few questions before starting the setup."
                                                                                                              e   cho "You can leave the default options and just press enter if you are ok with them."
                                                                                                              echo
                                                                                                              echo "First, provide the IPv4 address of the netw   ork interface you want OpenVPN"
                                                                                                              echo "listening to."
                                                                                                              # Autodetect IP     address and pre-fill for the user
                                                                                                              IP=$(ip addr | grep 'inet' | grep -v   inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
                                                                                                              read -p "IP address: "   -e -i $IP IP
                                                                                                              # If $IP is a private IP address, the server must be beh  ind NAT
                                                                                                              if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|  172\.3[01]\.|192\.168)'; then
                                                                                                                echo
                                                                                                                echo "This server is behind NAT.         What is the public IPv4 address or hostname?"
                                                                                                                read -p "Public IP add    ress / hostname: " -e PUBLICIP
                                                                                                              fi
                                                                                                              echo
                                                                                                              echo "Which protocol do you w     ant for OpenVPN connections?"
                                                                                                              echo "   1) UDP (recommended)"
                                                                                                              echo "       2) TCP"
                                                                                                              read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
                                                                                                              case $PROTOCOL i    n
                                                                                                                1)
                                                                                                                  PROTOCOL=udp
                                                                                                                  ;;
                                                                                                                2)
                                                                                                                  PROTOCOL=tcp
                                                                                                                  ;;
                                                                                                              esac
                                                                                                              echo
                                                                                                              echo                               "What port do you want OpenVPN listening to?"
                                                                                                              read -p "Port: " -e -i  1194 PORT
                                                                                                              echo
                                                                                                              echo "Which DNS do you want to use with the VPN?"
                                                                                                              ech     o "   1) Current system resolvers"
                                                                                                              echo "   2) 1.1.1.1"
                                                                                                              echo "   3) G   oogle"
                                                                                                              echo "   4) OpenDNS"
                                                                                                              echo "   5) Verisign"
                                                                                                              read -p "DNS [1-5]      : " -e -i 1 DNS
                                                                                                              echo
                                                                                                              echo "Finally, tell me your name for the client     certificate."
                                                                                                              echo "Please, use one word only, no special characters."
                                                                                                              read -p "Client name: " -e -i client CLIENT
                                                                                                              echo
                                                                                                              echo "Okay, that w      as all I needed. We are ready to set up your OpenVPN server now."
                                                                                                              read   -n1 -r -p "Press any key to continue..."
                                                                                                              if [[ "$OS" = 'debian'  ]]; t hen
                                                                                                                apt-get update
                                                                                                                apt-get install openvpn iptables openssl ca-cert        ificates -y
                                                                                                              else
                                                                                                                # Else, the distro is CentOS
                                                                                                                yum install epel-rel          ease -y
                                                                                                                yum install openvpn iptables openssl ca-certificates -y
                                                                                                              fi
                                                                                                                      # Get easy-rsa
                                                                                                                      EASYRSAURL='https://github.com/OpenVPN/easy-rsa/release s/download/v3.0.4/EasyRSA-3.0.4.tgz'
                                                                                                                      wget -O ~/easyrsa.tgz "$EASYRSAUR L" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
                                                                                                                      tar xzf ~/easyr sa.tgz -C ~/
                                                                                                                      mv ~/EasyRSA-3.0.4/ /etc/openvpn/
                                                                                                                      mv /etc/openvpn/EasyRS    A-3.0.4/ /etc/openvpn/easy-rsa/
                                                                                                                      chown -R root:root /etc/openvpn/easy-r  sa/
                                                                                                                      rm -f ~/easyrsa.tgz
                                                                                                                      cd /etc/openvpn/easy-rsa/
                                                                                                                      # Create the PKI,       set up the CA, the DH params and the server + client certificates
                                                                                                                      ./ea  syrsa init-pki
                                                                                                                      ./easyrsa --batch build-ca nopass
                                                                                                                      ./easyrsa gen-dh
                                                                                                                      ./      easyrsa build-server-full server nopass
                                                                                                                      ./easyrsa build-client-full $C  LIENT nopass
                                                                                                                      EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
                                                                                                                      # Move the stuff     we need
                                                                                                                      cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server .crt pki/private/server.key pki/crl.pem /etc/openvpn
                                                                                                                      # CRL is read wit h each client connection, when OpenVPN is dropped to nobody
                                                                                                                      chown nobo  dy:$GROUPNAME /etc/openvpn/crl.pem
                                                                                                                      # Generate key for tls-auth
                                                                                                                      openvp    n --genkey --secret /etc/openvpn/ta.key
                                                                                                                      # Generate server.conf
                                                                                                                      echo "    port $PORT
                                                                                                                      proto $PROTOCOL
                                                                                                                      dev tun
                                                                                                                      sndbuf 0
                                                                                                                      rcvbuf 0
                                                                                                                      ca ca.crt
                                                                                                                      cert server.crt
                                                                                                                      key server.key
                                                                                                                      dh dh.pem
                                                                                                                      auth SHA512
                                                                                                                      tls-auth ta.key 0
                                                                                                                      topology subnet
                                                                                                                      server 10.8.0.0 255.255.255.0
                                                                                                                      ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
                                                                                                                      echo 'push "redirect-gateway def1 bypass-dhcp"' >> /et  c/openvpn/server.conf
                                                                                                                      # DNS
                                                                                                                      case $DNS in
                                                                                                                        1)
                                                                                                                          # Locate the proper r           esolv.conf
                                                                                                                          # Needed for systems running systemd-resolved
                                                                                                                          if grep -q         "127.0.0.53" "/etc/resolv.conf"; then
                                                                                                                            RESOLVCONF='/run/systemd/reso     lve/resolv.conf'
                                                                                                                          else
                                                                                                                            RESOLVCONF='/etc/resolv.conf'
                                                                                                                          fi
                                                                                                                          # Obtai                 n the resolvers from resolv.conf and use them for OpenVPN
                                                                                                                          grep -v '#'    $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
                                                                                                                          echo "push \"dhcp-option D      NS $line\"" >> /etc/openvpn/server.conf
                                                                                                                        done
                                                                                                                        ;;
                                                                                                                      2)
                                                                                                                        echo 'push "                dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
                                                                                                                        echo 'push "dhc   p-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
                                                                                                                        ;;
                                                                                                                      3)
                                                                                                                        echo 'pu            sh "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
                                                                                                                        echo 'push    "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
                                                                                                                        ;;
                                                                                                                      4)
                                                                                                                        echo             'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
                                                                                                                            echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
                                                                                                                            ;;
                                                                                                                          5)
                                                                                                                            echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/s           erver.conf
                                                                                                                            echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/se    rver.conf
                                                                                                                            ;;
                                                                                                                        esac
                                                                                                                        echo "keepalive 10 120
                                                                                                                        cipher AES-256-CBC
                                                                                                                        user no       body
                                                                                                                        group $GROUPNAME
                                                                                                                        persist-key
                                                                                                                        persist-tun
                                                                                                                        status openvpn-status.log
                                                                                                                        verb 3
                                                                                                                        crl-verify crl.pem" >> /etc/openvpn/server.conf
                                                                                                                        # Enable net.ipv4.ip_forward fo r the system
                                                                                                                        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-f orward.conf
                                                                                                                        # Enable without waiting for a reboot or service restart
                                                                                                                            echo 1 > /proc/sys/net/ipv4/ip_forward
                                                                                                                            if pgrep firewalld; then
                                                                                                                              # Us      ing both permanent and not permanent rules to avoid a firewalld
                                                                                                                              # rel   oad.
                                                                                                                              # We don't use --add-service=openvpn because that would only wor    k with
                                                                                                                              # the default port and protocol.
                                                                                                                              firewall-cmd --zone=public        --add-port=$PORT/$PROTOCOL
                                                                                                                              firewall-cmd --zone=trusted --add-source=1    0.8.0.0/24
                                                                                                                              firewall-cmd --permanent --zone=public --add-port=$PORT/$P    ROTOCOL
                                                                                                                              firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0   /24
                                                                                                                              # Set NAT for the VPN subnet
                                                                                                                              firewall-cmd --direct --add-rule i        pv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                                                                                                              firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/2   4 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                                                                                                            else
                                                                                                                              # Needed to use rc.local wi     th some systemd distros
                                                                                                                              if [[ "$OS" = 'debian' && ! -e $RCLOCAL  ]]; t    hen
                                                                                                                                echo '#!/bin/sh -e
                                                                                                                                exit 0' > $RCLOCAL
                                                                                                                              fi
                                                                                                                              chmod +x $RCLOCAL
                                                                                                                                              # Set NAT for the VPN subnet
                                                                                                                                              iptables -t nat -A POSTROUTING -s 10.8.     0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
                                                                                                                                              sed -i "1 a\iptables -t nat     -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
                                                                                                                                              if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
                                                                                                                                                # If iptables has at           least one REJECT rule, we asume this is needed.
                                                                                                                                                # Not the best appr     oach but I can't think of other and this shouldn't
                                                                                                                                                # cause problems.
                                                                                                                                                iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
                                                                                                                                                iptables            -I FORWARD -s 10.8.0.0/24 -j ACCEPT
                                                                                                                                                iptables -I FORWARD -m state --s      tate RELATED,ESTABLISHED -j ACCEPT
                                                                                                                                                sed -i "1 a\iptables -I INPUT -p      $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
                                                                                                                                                sed -i "1 a\iptables -I       FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
                                                                                                                                                sed -i "1 a\iptables -I F     ORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
                                                                                                                                              fi
                                                                                                                                              f     i
                                                                                                                                              # If SELinux is enabled and a custom port was selected, we need this
                                                                                                                                              if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" & & [[ "$PORT" != '1194'  ]]; then
                                                                                                                                                # Install semanage if not already pre   sent
                                                                                                                                                if ! hash semanage 2>/dev/null; then
                                                                                                                                                  yum install policycoreut          ils-python -y
                                                                                                                                                fi
                                                                                                                                                semanage port -a -t openvpn_port_t -p $PROTOCOL $P        ORT
                                                                                                                                              fi
                                                                                                                                              # And finally, restart OpenVPN
                                                                                                                                              if [[ "$OS" = 'debian'  ]]; the     n
                                                                                                                                                # Little hack to check for systemd
                                                                                                                                                if pgrep systemd-journal; then
                                                                                                                                                  systemctl restart openvpn@server.service
                                                                                                                                                else
                                                                                                                                                  /etc/init.d/open                vpn restart
                                                                                                                                                fi
                                                                                                                                              else
                                                                                                                                                if pgrep systemd-journal; then
                                                                                                                                                  systemctl re                start openvpn@server.service
                                                                                                                                                  systemctl enable openvpn@server.service
                                                                                                                                                else
                                                                                                                                                  service openvpn restart
                                                                                                                                                  chkconfig openvpn on
                                                                                                                                                fi
                                                                                                                                              fi
                                                                                                                                              #                         If the server is behind a NAT, use the correct IP address
                                                                                                                                              if [[ "$PUBL  ICIP" != ""  ]]; then
                                                                                                                                                IP=$PUBLICIP
                                                                                                                                              fi
                                                                                                                                              # client-common.txt is created         so we have a template to add further users later
                                                                                                                                              echo "client
                                                                                                                                              dev tun
                                                                                                                                              proto $PROTOCOL
                                                                                                                                              sndbuf 0
                                                                                                                                              rcvbuf 0
                                                                                                                                              remote $IP $PORT
                                                                                                                                              resolv-retry infinite
                                                                                                                                              nobind
                                                                                                                                              persist-key
                                                                                                                                              persist-tun
                                                                                                                                              remote-cert-tls server
                                                                                                                                              auth SHA512
                                                                                                                                              cipher AES-256-CBC
                                                                                                                                              setenv opt block-outside-dns
                                                                                                                                              key-direction 1
                                                                                                                                              verb 3" > /etc/openvpn/client-common.txt
                                                                                                                                              # Generates the cu  stom client.ovpn
                                                                                                                                              newclient "$CLIENT"
                                                                                                                                              echo
                                                                                                                                              echo "Finished!"
                                                                                                                                              echo
                                                                                                                                              ec          ho "Your client configuration is available at:" ~/"$CLIENT.ovpn"
                                                                                                                                              echo  "If you want to add more clients, you simply need to run this script again!"
                                                                                                    fi
