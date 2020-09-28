#!/bin/bash

NAME="Shadowsocks"
NAME_BIN="./shadowsocks-go "
FOLDER="/usr/local/shadowsocks-go"
CONF="/usr/local/shadowsocks-go/shadowsocks-go.conf"
LOG="/usr/local/shadowsocks-go/shadowsocks-go.log"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[info]${Font_color_suffix}"
Error="${Red_font_prefix}[error]${Font_color_suffix}"
RETVAL=0

check_running(){
	PID=$(ps -ef |grep "${NAME_BIN}" |grep -v "grep" |grep -v "init.d" |grep -v "service" |awk '{print $2}')
	if [[ ! -z ${PID} ]]; then
		return 0
	else
		return 1
	fi
}
read_config(){
	[[ ! -e ${CONF} ]] && echo -e "${Error} $NAME config file is not found!" && exit 1
	port=$(cat ${CONF}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
	password=$(cat ${CONF}|grep 'PASSWORD = '|awk -F 'PASSWORD = ' '{print $NF}')
	cipher=$(cat ${CONF}|grep 'CIPHER = '|awk -F 'CIPHER = ' '{print $NF}')
	verbose=$(cat ${CONF}|grep 'VERBOSE = '|awk -F 'VERBOSE = ' '{print $NF}')
	if [[ "${verbose}" == "YES" ]]; then
		verbose="-verbose"
	else
		verbose=""
	fi
}
do_start(){
	check_running
	if [[ $? -eq 0 ]]; then
		echo -e "${Info} $NAME (PID ${PID}) is running..." && exit 0
	else
		read_config
		cd ${FOLDER}
		echo -e "${Info} $NAME is starting..."
		ulimit -n 51200
		nohup ./shadowsocks-go -s ":${port}" -cipher "${cipher}" -password "${password}" "${verbose}" >> "${LOG}" 2>&1 &
		sleep 2s
		check_running
		if [[ $? -eq 0 ]]; then
			echo -e "${Info} $NAME is running!"
		else
			echo -e "${Error} $NAME is not running!"
		fi
	fi
}
do_stop(){
	check_running
	if [[ $? -eq 0 ]]; then
		kill -9 ${PID}
		RETVAL=$?
		if [[ $RETVAL -eq 0 ]]; then
			echo -e "${Info} $NAME has stopped!"
		else
			echo -e "${Error} $NAME has not stopped!"
		fi
	else
		echo -e "${Info} $NAME is not runing"
		RETVAL=1
	fi
}
do_status(){
	check_running
	if [[ $? -eq 0 ]]; then
		echo -e "${Info} $NAME (PID ${PID}) is running..."
	else
		echo -e "${Info} $NAME is not running!"
		RETVAL=1
	fi
}
do_restart(){
	do_stop
	do_start
}
case "$1" in
	start|stop|restart|status)
	do_$1
	;;
	*)
	echo "Usage: $0 { start | stop | restart | status }"
	RETVAL=1
	;;
esac
exit $RETVAL