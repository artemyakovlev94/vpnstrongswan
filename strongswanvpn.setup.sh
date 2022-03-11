#!/bin/bash
#    strongSwan VPN server installer for Debian
#
#    Copyright (C) 2022 Artem Yakovlev <artem.yakovlev94@icloud.com>

echo ""
echo "******************************************************************"
echo "*"
echo "* strongSwan VPN server installer for Debian *"
echo "*"
echo "* Copyright (C) 2022 Artem Yakovlev <artem.yakovlev94@icloud.com>"
echo "*"
echo "******************************************************************"
echo ""

if [ `id -u` -ne 0 ]
then
  echo "Please start this script with root privileges!"
  echo "Try again with sudo."
  exit 0
fi

# *** Variables ***
CERT_CA=ca
SERVER_IP_ADDRESS=127.0.0.1
SERVER_NAME=VPN
USER_NAME=user
USER_PASSWORD=12345

MOBILECONFIG_PATH=/etc/ipsec.d
MOBILECONFIG_SH=mobileconfig.sh
MOBILECONFIG_CONF=iphone.mobileconfig
# *****************

installPackagesVPNServer() {
	
	apt-get update
	apt-get upgrade
	apt-get install wget
	apt-get install strongswan
	apt-get install libstrongswan-standard-plugins
	apt-get install strongswan-pki
	apt-get install libcharon-extra-plugins
	apt-get install libcharon-extauth-plugins
	apt-get install zsh
	apt-get install iptables-persistent

	echo "StrongSwan VPN Server packages have been installed"
}

removePackagesVPNServer() {

	apt-get remove wget
	apt-get remove strongswan
	apt-get remove libstrongswan-standard-plugins
	apt-get remove strongswan-pki
	apt-get remove libcharon-extra-plugins
	apt-get remove libcharon-extauth-plugins
	apt-get remove zsh
	apt-get remove iptables-persistent

	echo "StrongSwan VPN Server packages have been removed"
}

# Create certificate root CA
createCertificateCA() {

	if [ -f "/etc/ipsec.d/private/$CERT_CA.pem" ]; then
		cp -p -f /etc/ipsec.d/private/$CERT_CA.pem /etc/ipsec.d/private/$CERT_CA.pem.backup
		rm /etc/ipsec.d/private/$CERT_CA.pem
	fi

	if [ -f "/etc/ipsec.d/cacerts/$CERT_CA.pem" ]; then
		cp -p -f /etc/ipsec.d/cacerts/$CERT_CA.pem /etc/ipsec.d/cacerts/$CERT_CA.pem.backup
		rm /etc/ipsec.d/cacerts/$CERT_CA.pem
	fi

	ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/$CERT_CA.pem
	ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/$CERT_CA.pem \
	--type rsa --digest sha256 \
	--dn "CN=$SERVER_NAME VPN root CA" \
	--outform pem > /etc/ipsec.d/cacerts/$CERT_CA.pem

	echo "StrongSwan VPN server CA root certificate has been created"
}

# Create certificate strongSwan VPN server
createCertificateServer() {

	if [ -f "/etc/ipsec.d/private/$SERVER_NAME.pem" ]; then
		cp -p -f /etc/ipsec.d/private/$SERVER_NAME.pem /etc/ipsec.d/private/$SERVER_NAME.pem.backup
		rm /etc/ipsec.d/private/$SERVER_NAME.pem
	fi

	if [ -f "/etc/ipsec.d/certs/$SERVER_NAME.pem" ]; then
		cp -p -f /etc/ipsec.d/certs/$SERVER_NAME.pem /etc/ipsec.d/certs/$SERVER_NAME.pem.backup
		rm /etc/ipsec.d/certs/$SERVER_NAME.pem
	fi

	ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/$SERVER_NAME.pem
	ipsec pki --pub --in /etc/ipsec.d/private/$SERVER_NAME.pem --type rsa |
	ipsec pki --issue --lifetime 3650 --digest sha256 \
	--cacert /etc/ipsec.d/cacerts/$CERT_CA.pem \
	--cakey /etc/ipsec.d/private/$CERT_CA.pem \
	--dn "CN=$SERVER_IP_ADDRESS" \
	--san $SERVER_IP_ADDRESS \
	--flag serverAuth \
	--outform pem > /etc/ipsec.d/certs/$SERVER_NAME.pem

	echo "The strongSwan VPN server certificate has been created"
}

# Edit ipsec.conf
editIPSecConfig() {

	if [ -f "/etc/ipsec.conf" ]; then
		cp -p -f /etc/ipsec.conf /etc/ipsec.conf.backup
	fi
	cat > /etc/ipsec.conf <<EOF
config setup
	uniqueids=never
	charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

conn %default
	auto=add
	keyexchange=ikev2
	type=tunnel
	ike=aes128gcm16-sha2_256-prfsha256-ecp256,chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
	esp=aes128gcm16-sha2_256-ecp256,chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
	fragmentation=yes
	rekey=no
	dpddelay=300s
	compress=yes
	dpdaction=clear
	left=%any
	leftauth=pubkey
	leftsourceip=$SERVER_IP_ADDRESS
	leftid=$SERVER_IP_ADDRESS
	leftcert=$SERVER_NAME.pem
	leftsendcert=always
	leftsubnet=0.0.0.0/0
	right=%any
	rightsourceip=10.10.10.0/24
	rightdns=8.8.8.8,8.8.4.4
	eap_identity=%identity

conn ikev2-pubkey
	rightauth=pubkey

conn ikev2-eap-mschapv2
	rightauth=eap-mschapv2
EOF

	echo "ipsec.conf has been edited"
}

# Edit ipsec.secrets
editIPSecSecrets() {

	if [ -f "/etc/ipsec.secrets" ]; then
		cp -p -f /etc/ipsec.secrets /etc/ipsec.secrets.backup
	fi
	cat > /etc/ipsec.secrets <<EOF
# This file holds shared secrets or RSA private keys for authentication.
# RSA private key for this host, authenticating it to any other host
# which knows the public part.  Suitable public keys, for ipsec.conf, DNS,
# or configuration of other implementations, can be extracted conveniently
# with "ipsec showhostkey".
#####################################################
: RSA "$SERVER_NAME.pem"
EOF

	echo "ipsec.secrets has been edited"
}

# Edit sysctl.conf
editSysctlConf() {

	if [ -f "/etc/sysctl.conf" ]; then
		cp -p -f /etc/sysctl.conf /etc/sysctl.conf.backup
	fi

	sed -i "/#net.ipv4.ip_forward=1/d" /etc/sysctl.conf
	sed -i "/#net.ipv4.conf.all.accept_redirects = 0/d" /etc/sysctl.conf
	sed -i "/#net.ipv4.conf.all.send_redirects = 0/d" /etc/sysctl.conf
	sed -i "/#net.ipv4.ip_no_pmtu_disc=1/d" /etc/sysctl.conf

	sed -i "/net.ipv4.ip_forward=1/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.all.accept_redirects = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.all.send_redirects = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.ip_no_pmtu_disc=1/d" /etc/sysctl.conf

	# включить переадресацию пакетов
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	# предотвратить MITM-атаки
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	# запретить отправку ICMP-редиректов
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	# запретить поиск PMTU
	echo "net.ipv4.ip_no_pmtu_disc=1" >> /etc/sysctl.conf

	# Подгрузим новые значения:
	sysctl -p

	echo "sysctl.conf has been edited"
}

# Edit Firewall
editFirewall() {

	# Очистим все цепочки
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -F
	iptables -Z

	# Разрешим соединения по SSH на 22 порту, чтобы не потерять доступ к машине:
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp --dport 22 -j ACCEPT

	# Разрешим соединения на loopback-интерфейсе:
	iptables -A INPUT -i lo -j ACCEPT

	# Теперь разрешим входящие соединения на UDP-портах 500 и 4500:
	iptables -A INPUT -p udp --dport  500 -j ACCEPT
	iptables -A INPUT -p udp --dport 4500 -j ACCEPT

	# Разрешим переадресацию ESP-трафика:
	iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.0/24 -j ACCEPT
	iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT

	# Настроим маскирование трафика, так как наш VPN-сервер, по сути, выступает как шлюз между Интернетом и VPN-клиентами:
	iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
	iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

	# Настроим максимальный размер сегмента пакетов:
	iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

	# Запретим все прочие соединения к серверу:
	iptables -A INPUT -j DROP
	iptables -A FORWARD -j DROP

	# Сохраним правила, чтобы они загружались после каждой перезагрузки:
	netfilter-persistent save
	netfilter-persistent reload

	echo "firewall has been edited"
}

installStrongSwanVPNServer() {

	# Подтверждение установки strongSwan VPN сервера
  echo "Do you want to install strongSwan VPN server? [Y/n]"
	read -p "" yn
	case $yn in
		[Yy]* ) break;;
		[Nn]* ) return;;
		* ) echo "Please answer with Yes or No [Y/n]";;
	esac

	# Ввод IP адреса сервера
	while true; do
		read -p "Enter the IP address of this server: " SERVER_IP_ADDRESS 
		if [ "$SERVER_IP_ADDRESS" != "" ]; then
			echo "Confirm the IP address of this server [" $SERVER_IP_ADDRESS "] [Y/n]:"
			read -p "" yn
			case $yn in
				[Yy]* ) break;;
				[Nn]* ) return;;
				* ) echo "Please answer with Yes or No [Y/n].";;
			esac
		fi
	done

	# Ввод наименования VPN сервера
	while true; do
		read -p "Enter the name of the future strongSwan VPN server: " SERVER_NAME 
		if [ "$SERVER_NAME" != "" ]; then
			echo "Confirm the name of the future strongSwan VPN server [" $SERVER_NAME "] [Y/n]:"
			read -p "" yn
			case $yn in
				[Yy]* ) break;;
				[Nn]* ) return;;
				* ) echo "Please answer with Yes or No [Y/n].";;
			esac
		fi
	done

	# Установить необходимые пакеты для strongSwan VPN сервера
	installPackagesVPNServer

	# Создать корневой сертификат центра сертификации strongSwan VPN сервера
	createCertificateCA

	# Создать сертификат strongSwan VPN сервера
	createCertificateServer

	# Отредактировать конфигурацию strongSwan VPN сервера (ipsec.conf)
	editIPSecConfig

	# Отредактировать файл ключей strongSwan VPN сервера (ipsec.secrets)
	editIPSecSecrets

	# Перезапустить strongSwan
	ipsec restart

	# Отредактировать сетевые параметры ядра strongSwan VPN сервера (sysctl.conf)
	editSysctlConf

	# Внесем изменения в Firewall
	editFirewall

	echo "The strongSwan VPN server has been installed. A server reboot is required to continue."
}

showCARootCertificate() {
	if [ -f "/etc/ipsec.d/cacerts/$CERT_CA.pem" ]; then
		cat /etc/ipsec.d/cacerts/$CERT_CA.pem
	else
		echo "CA root certificate doesn't exist"
	fi
}

# Добавить пользователя strongSwan VPN сервера
addVPNUser() {

	# Ввод имени нового пользователя
	while true; do
		read -p "Enter user name: " USER_NAME 
		if [ "$USER_NAME" != "" ]; then
			if [ "$USER_NAME" = "exit" ]; then
				return
			else
				if [ -f "/etc/ipsec.d/private/$USER_NAME.pem" ] || [ -f "/etc/ipsec.d/certs/$USER_NAME.pem" ]; then
					echo "A user with the same name already exists"
				else
					break
				fi
			fi
		fi
	done

	# Ввод пароля нового пользователя
	while true; do
		read -p "Input user password: " USER_PASSWORD 
		if [ "$USER_PASSWORD" != "" ]; then
			if [ "$USER_PASSWORD" = "exit" ]; then
				return
			else
				break
			fi
		fi
	done

	ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/$USER_NAME.pem
	ipsec pki --pub --in /etc/ipsec.d/private/$USER_NAME.pem --type rsa |
	ipsec pki --issue --lifetime 3650 --digest sha256 \
	--cacert /etc/ipsec.d/cacerts/$CERT_CA.pem \
	--cakey /etc/ipsec.d/private/$CERT_CA.pem \
	--dn "CN=$USER_NAME" \
	--san me \
	--flag clientAuth \
	--outform pem > /etc/ipsec.d/certs/$USER_NAME.pem

	echo "StrongSwan VPN server user certificate created"

	echo "$USER_NAME : EAP \"$USER_PASSWORD\"" >> /etc/ipsec.secrets

	echo "User \"$USER_NAME\" has been created"
}

# Сформировать профиль конфигурации VPN для iPhone
getVPNProfileIPhone() {

	while true; do
		read -p "Enter user name: " USER_NAME 
		if [ "$USER_NAME" != "" ]; then
			if [ "$USER_NAME" = "exit" ]; then
				return
			else
				if [ -f "/etc/ipsec.d/private/$USER_NAME.pem" ] && [ -f "/etc/ipsec.d/certs/$USER_NAME.pem" ]; then
					break
				else
					echo "User with this name does not exist"
				fi
			fi
		fi
	done

	# IP Адрес сервера
	while true; do
		read -p "Enter the IP address of this strongSwan VPN server: " SERVER_IP_ADDRESS 
		if [ "$SERVER_IP_ADDRESS" != "" ]; then
			if [ "$USER_NAME" = "exit" ]; then
				return
			else
				break;
			fi
		fi
	done

	# Наименование сервера
	while true; do
		read -p "Enter the name of this strongSwan VPN server: " SERVER_NAME 
		if [ "$SERVER_NAME" != "" ]; then
			if [ "$USER_NAME" = "exit" ]; then
				return
			else
				break;
			fi
		fi
	done

	if [ -f "$MOBILECONFIG_PATH/$MOBILECONFIG_SH" ]; then
		rm $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	fi

	wget -P $MOBILECONFIG_PATH https://raw.githubusercontent.com/artemyakovlev94/vpnstrongswan/main/mobileconfig.sh

	sed -i "s/CLIENT=\"client_name\"/CLIENT=\"$USER_NAME\"/" $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	sed -i "s/SERVER=\"server_name\"/SERVER=\"$SERVER_NAME\"/" $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	sed -i "s/FQDN=\"server_ip\"/FQDN=\"$SERVER_IP_ADDRESS\"/" $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	sed -i "s/CA=\"ca\"/CA=\"$CERT_CA\"/" $MOBILECONFIG_PATH/$MOBILECONFIG_SH

	chmod u+x $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	$MOBILECONFIG_PATH/$MOBILECONFIG_SH > $MOBILECONFIG_PATH/$MOBILECONFIG_CONF

	cat $MOBILECONFIG_PATH/$MOBILECONFIG_CONF

	if [ -f "$MOBILECONFIG_PATH/$MOBILECONFIG_SH" ]; then
		rm $MOBILECONFIG_PATH/$MOBILECONFIG_SH
	fi

	if [ -f "$MOBILECONFIG_PATH/$MOBILECONFIG_CONF" ]; then
		rm $MOBILECONFIG_PATH/$MOBILECONFIG_CONF
	fi
}

# Show VPN Users and Passwords
showVPNUsers() {
	echo ""
	echo "=========== VPN Users ==========="
	echo ""
	grep -i " : EAP " /etc/ipsec.secrets
	echo ""
	echo "================================="
	echo ""
}

while true; do

	echo ""
	echo "*******************************************"
	echo "* 1 - Install strongSwan VPN server"
	echo "* 2 - Show VPN Server CA Root Certificate"
	echo "* 3 - Add strongSwan VPN server user"
	echo "* 4 - Get VPN Configuration Profile for iPhone"
	echo "* 5 - Show VPN Users and Passwords"
	echo "* 0 - Exit setup"
	echo "*******************************************"

  read -p "" yn
  case $yn in
		[1]* ) installStrongSwanVPNServer;;
		[2]* ) showCARootCertificate;;
		[3]* ) addVPNUser;;
		[4]* ) getVPNProfileIPhone;;
		[5]* ) showVPNUsers;;
		[0]* ) break;;
		* ) echo "Select a menu item.";;
  esac
done

echo "strongSwan VPN server installer for Debian has been closed"
