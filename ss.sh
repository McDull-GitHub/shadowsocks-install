#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
FOLDER="/usr/local/shadowsocks-go"
FILE="/usr/local/shadowsocks-go/shadowsocks-go"
CONF="/usr/local/shadowsocks-go/shadowsocks-go.conf"
LOG="/usr/local/shadowsocks-go/shadowsocks-go.log"
Now_ver_File="/usr/local/shadowsocks-go/ver.txt"
Crontab_file="/usr/bin/crontab"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[info]${Font_color_suffix}"
Error="${Red_font_prefix}[error]${Font_color_suffix}"
Tip="${Green_font_prefix}[note]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} ROOT is required" && exit 1
}

check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_installed_status(){
	[[ ! -e ${FILE} ]] && echo -e "${Error} Shadowsocks is not installed!" && exit 1
}
check_crontab_installed_status(){
	if [[ ! -e ${Crontab_file} ]]; then
		echo -e "${Error} Crontab is not installed. Start installing..."
		if [[ ${release} == "centos" ]]; then
			yum install crond -y
		else
			apt-get install cron -y
		fi
		if [[ ! -e ${Crontab_file} ]]; then
			echo -e "${Error} Crontab cannot be installed!" && exit 1
		else
			echo -e "${Info} Crontab is installed"
		fi
	fi
}
check_pid(){
	PID=$(ps -ef| grep "./shadowsocks-go "| grep -v "grep" | grep -v "init.d" |grep -v "service" |awk '{print $2}')
}
check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/shadowsocks/go-shadowsocks2/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
	[[ -z ${new_ver} ]] && echo -e "${Error} Shadowsocks " && exit 1
	echo -e "${Info} The latest version of Shadowsocks is [ ${new_ver} ]"
}
check_ver_comparison(){
	now_ver=$(cat ${Now_ver_File})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
        check_pid
        [[ ! -z $PID ]] && kill -9 ${PID}
        \cp "${CONF}" "/tmp/shadowsocks-go.conf"
        rm -rf ${FOLDER}
        Download
        mv "/tmp/shadowsocks-go.conf" "${CONF}"
        Start
	else
		echo -e "${Info} Shadowsocks is up to date [ ${new_ver} ]" && exit 1
	fi
}
Download(){
	if [[ ! -e "${FOLDER}" ]]; then
		mkdir "${FOLDER}"
	else
		[[ -e "${FILE}" ]] && rm -rf "${FILE}"
	fi
	cd "${FOLDER}"
	if [[ ${bit} == "x86_64" ]]; then
		wget --no-check-certificate -N "https://github.com/shadowsocks/go-shadowsocks2/releases/download/${new_ver}/shadowsocks2-linux.gz"
	else
		echo -e "${Error} Not supported" && rm -rf "${FOLDER}" && exit 1
	fi
	[[ ! -e "shadowsocks2-linux.gz" ]] && echo -e "${Error} Cannot download Shadowsocks" && rm -rf "${FOLDER}" && exit 1
	gzip -d "shadowsocks2-linux.gz"
	[[ ! -e "shadowsocks2-linux" ]] && echo -e "${Error} Cannot unzip Shadowsocks!" && rm -rf "${FOLDER}" && exit 1
	mv "shadowsocks2-linux" "shadowsocks-go"
	[[ ! -e "shadowsocks-go" ]] && echo -e "${Error} Cannot rename Shadowsocks!" && rm -rf "${FOLDER}" && exit 1
	chmod +x shadowsocks-go
	echo "${new_ver}" > ${Now_ver_File}
}
Service(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/McDull-GitHub/shadowsocks-install/master/ss-centos.sh" -O /etc/init.d/ss-go; then
			echo -e "${Error} Shadowsocks deamon cannot be downloaded!"
			rm -rf "${FOLDER}"
			exit 1
		fi
		chmod +x "/etc/init.d/ss-go"
		chkconfig --add ss-go
		chkconfig ss-go on
	else
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/McDull-GitHub/shadowsocks-install/master/ss-debian.sh" -O /etc/init.d/ss-go; then
			echo -e "${Error} Shadowsocks deamon cannot be downloaded!"
			rm -rf "${FOLDER}"
			exit 1
		fi
		chmod +x "/etc/init.d/ss-go"
		update-rc.d -f ss-go defaults
	fi
}
Installation_dependency(){
	gzip_ver=$(gzip -V)
	if [[ -z ${gzip_ver} ]]; then
		if [[ ${release} == "centos" ]]; then
			yum update
			yum install -y gzip
		else
			apt-get update
			apt-get install -y gzip
		fi
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}
Write_config(){
	cat > ${CONF}<<-EOF
PORT = ${ss_port}
PASSWORD = ${ss_password}
CIPHER = ${ss_cipher}
VERBOSE = ${ss_verbose}
EOF
}
Read_config(){
	[[ ! -e ${CONF} ]] && echo -e "${Error} Shadowsocks config file is not found!" && exit 1
	port=$(cat ${CONF}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
	password=$(cat ${CONF}|grep 'PASSWORD = '|awk -F 'PASSWORD = ' '{print $NF}')
	cipher=$(cat ${CONF}|grep 'CIPHER = '|awk -F 'CIPHER = ' '{print $NF}')
	verbose=$(cat ${CONF}|grep 'VERBOSE = '|awk -F 'VERBOSE = ' '{print $NF}')
}
Set_port(){
	while true
		do
		echo -e "Shadowsocks port [1-65535]"
		read -e -p "(default: 12345):" ss_port
		[[ -z "${ss_port}" ]] && ss_port="12345"
		echo $((${ss_port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${ss_port} -ge 1 ]] && [[ ${ss_port} -le 65535 ]]; then
				echo && echo "================================================"
				echo -e "	The port is ${Red_background_prefix} ${ss_port} ${Font_color_suffix}"
				echo "================================================" && echo
				break
			else
				echo "Please input a Shadowsocks port [1-65535]"
			fi
		else
			echo "Please input a Shadowsocks port [1-65535]"
		fi
		done
}
Set_password(){
	echo "Shadowsocks password [0-9][a-z][A-Z]"
	read -e -p "(default: password):" ss_password
	[[ -z "${ss_password}" ]] && ss_password="password"
	echo && echo "================================================"
	echo -e "	The password is ${Red_background_prefix} ${ss_password} ${Font_color_suffix}"
	echo "================================================" && echo
}
Set_cipher(){
	ss_cipher="aead_chacha20_poly1305"
}
Set_verbose(){
	echo -e "Do you need logs？[Y/N]"
	read -e -p "(default: N):" ss_verbose
	[[ -z "${ss_verbose}" ]] && ss_verbose="N"
	if [[ "${ss_verbose}" == [Yy] ]]; then
		ss_verbose="YES"
	else
		ss_verbose="NO"
	fi
}
Set(){
	check_installed_status
	echo && echo -e "What do you want to do？
 ${Green_font_prefix}1.${Font_color_suffix}  Change port
 ${Green_font_prefix}2.${Font_color_suffix}  Change password" && echo
	read -e -p "(default: do nothing):" ss_modify
	[[ -z "${ss_modify}" ]] && echo "do nothing..." && exit 1
	if [[ "${ss_modify}" == "1" ]]; then
		Read_config
		Set_port
		ss_password=${password}
		ss_cipher=${cipher}
		ss_verbose=${verbose}
		Write_config
		Del_iptables
		Add_iptables
		Restart
	elif [[ "${ss_modify}" == "2" ]]; then
		Read_config
		Set_password
		ss_port=${port}
		ss_cipher=${cipher}
		ss_verbose=${verbose}
		Write_config
		Restart
	else
		echo -e "${Error} What do you want to do? (1-2)" && exit 1
	fi
}
Install(){
	check_root
	[[ -e ${FILE} ]] && echo -e "${Error} Shadowsocks is installed!" && exit 1
	Set_port
	Set_password
	Set_cipher
	Set_verbose
	Installation_dependency
	check_new_ver
	Download
	Service
	Write_config
	Set_iptables
	Add_iptables
	Save_iptables
	Start
}
Start(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} Shadowsocks is running!" && exit 1
	/etc/init.d/ss-go start
	check_pid
	[[ ! -z ${PID} ]] && View
}
Stop(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} Shadowsocks is not running!" && exit 1
	/etc/init.d/ss-go stop
}
Restart(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ss-go stop
	/etc/init.d/ss-go start
	check_pid
	[[ ! -z ${PID} ]] && View
}
Update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
}
Uninstall(){
	check_installed_status
	echo "Wanna uninstall Shadowsocks ? (Y/N)"
	echo
	read -e -p "(default: N):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z $PID ]] && kill -9 ${PID}
		if [[ -e ${CONF} ]]; then
			port=$(cat ${CONF}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
			Del_iptables
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ss-go.sh monitor") ]]; then
			crontab_monitor_cron_stop
		fi
		rm -rf "${FOLDER}"
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ss-go
		else
			update-rc.d -f ss-go remove
		fi
		rm -rf "/etc/init.d/ss-go"
		echo && echo "Shadowsocks is uninstalled !" && echo
	else
		echo && echo "Cancelled" && echo
	fi
}
getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}
getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
			cipher_1="chacha20-ietf-poly1305"
		else
			cipher_1=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
		fi
		SSbase64=$(urlsafe_base64 "${cipher_1}:${password}@${ipv4}:${port}")
		SSurl="ss://${SSbase64}"
		ss_link_ipv4="[ipv4]: ${Red_font_prefix}${SSurl}${Font_color_suffix}"
	fi
	if [[ "${ipv6}" != "IPv6_Error" ]]; then
		if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
			cipher_1="chacha20-ietf-poly1305"
		else
			cipher_1=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
		fi
		SSbase64=$(urlsafe_base64 "${cipher_1}:${password}@${ipv6}:${port}")
		SSurl="ss://${SSbase64}"
		ss_link_ipv6="[ipv6]: ${Red_font_prefix}${SSurl}${Font_color_suffix}"
	fi
}
View(){
	check_installed_status
	Read_config
	getipv4
	getipv6
	ss_link_qr
	if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
		cipher_2="chacha20-ietf-poly1305"
	else
		cipher_2=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
	fi
	clear && echo
	echo -e "———————————"
	echo -e "Shadowsocks"
	echo -e "———————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " ipv4\t\t->\t ${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " ipv6\t\t->\t ${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " port\t\t->\t ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " password\t->\t ${Green_font_prefix}${password}${Font_color_suffix}"
	[[ ! -z "${ss_link_ipv4}" ]] && echo -e "${ss_link_ipv4}"
	[[ ! -z "${ss_link_ipv6}" ]] && echo -e "${ss_link_ipv6}"
}
View_Log(){
	check_installed_status
	[[ ! -e ${LOG} ]] && echo -e "${Error} Shadowsocks logs is not found!" && exit 1
	tail -f ${LOG}
}

View_user_connection_info_1(){
	format_1=$1
	Read_config
	user_IP=$(ss state connected sport = :${port} -tn|sed '1d'|awk '{print $NF}'|awk -F ':' '{print $(NF-1)}'|sort -u)
	if [[ -z ${user_IP} ]]; then
		user_IP_total="0"
		echo -e "port: ${Green_font_prefix}"${port}"${Font_color_suffix}\t Number of Users: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t User IP: "
	else
		user_IP_total=$(echo -e "${user_IP}"|wc -l)
		if [[ ${format_1} == "IP_address" ]]; then
			echo -e "port: ${Green_font_prefix}"${port}"${Font_color_suffix}\t Number of Users: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t User IP: "
			get_IP_address
			echo
		else
			user_IP=$(echo -e "\n${user_IP}")
			echo -e "Number of Users: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\nUser IP ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		fi
	fi
	user_IP=""
}
View_user_connection_info(){
	check_installed_status
	View_user_connection_info_1
}
get_IP_address(){
	if [[ ! -z ${user_IP} ]]; then
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=$(echo "${user_IP}" |sed -n "$integer_1"p)
			IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
			echo -e "${Green_font_prefix}${IP}${Font_color_suffix} (${IP_address})"
			sleep 1s
		done
	fi
}
Set_crontab_monitor(){
	check_crontab_installed_status
	crontab_monitor_status=$(crontab -l|grep "ss-go.sh monitor")
	if [[ -z "${crontab_monitor_status}" ]]; then
		echo && echo -e "Status: ${Red_font_prefix}RUNNING${Font_color_suffix}" && echo
		echo -e "Do you want to turn on ${Green_font_prefix}Shadowsocks crontab monitor${Font_color_suffix}?[Y/N]"
		read -e -p "(default: y):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="y"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_start
		else
			echo && echo "Cancelled..." && echo
		fi
	else
		echo && echo -e "Status: ${Green_font_prefix}Stoped${Font_color_suffix}" && echo
		echo -e "Do you want to turn off ${Red_font_prefix}Shadowsocks crontab monitor${Font_color_suffix}?[Y/N]"
		read -e -p "(default: n):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="n"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_stop
		else
			echo && echo "Cancelled..." && echo
		fi
	fi
}
crontab_monitor_cron_start(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/ss-go.sh monitor/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/ss-go.sh monitor" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "ss-go.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Shadowsocks crontab monitor is off!" && exit 1
	else
		echo -e "${Info} Shadowsocks crontab monitor is on!"
	fi
}
crontab_monitor_cron_stop(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/ss-go.sh monitor/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "ss-go.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Shadowsocks crontab monitor is on!" && exit 1
	else
		echo -e "${Info} Shadowsocks crontab monitor is off!"
	fi
}
crontab_monitor(){
	check_installed_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks is not running, staring..." | tee -a ${LOG}
		/etc/init.d/ss-go start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks can't run..." | tee -a ${LOG}
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks is running..." | tee -a ${LOG}
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks is running..." | tee -a ${LOG}
	fi
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}

check_sys
action=$1
if [[ "${action}" == "monitor" ]]; then
	crontab_monitor
else
	echo && echo -e "  
————————————————————————————————
 ${Green_font_prefix} 1.${Font_color_suffix} install Shadowsocks
 ${Green_font_prefix} 2.${Font_color_suffix} update Shadowsocks
 ${Green_font_prefix} 3.${Font_color_suffix} uninstall Shadowsocks
————————————————————————————————
 ${Green_font_prefix} 4.${Font_color_suffix} start Shadowsocks
 ${Green_font_prefix} 5.${Font_color_suffix} stop Shadowsocks
 ${Green_font_prefix} 6.${Font_color_suffix} restart Shadowsocks
————————————————————————————————
 ${Green_font_prefix} 7.${Font_color_suffix} config Shadowsocks info
 ${Green_font_prefix} 8.${Font_color_suffix} show Shadowsocks info
 ${Green_font_prefix} 9.${Font_color_suffix} view user connection info
————————————————————————————————" && echo
	if [[ -e ${FILE} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Status: ${Green_font_prefix}installed${Font_color_suffix} and ${Green_font_prefix}running${Font_color_suffix}"
		else
			echo -e " Status: ${Green_font_prefix}installed${Font_color_suffix} but ${Red_font_prefix}not running${Font_color_suffix}"
		fi
	else
		echo -e " Status: ${Red_font_prefix}not installed${Font_color_suffix}"
	fi
	echo
	read -e -p " What do you want to do? [1-9]:" num
	case "$num" in
		1)
		Install
		;;
		2)
		Update
		;;
		3)
		Uninstall
		;;
		4)
		Start
		;;
		5)
		Stop
		;;
		6)
		Restart
		;;
		7)
		Set
		;;
		8)
		View
		;;
		9)
		View_user_connection_info
		;;
		*)
		echo "What do you want to do? [1-9]"
		;;
	esac
fi
