#! /bin/bash

if [ -z "$1" ]; then
	cat <<EOF
No host specified!

This script takes a pre-shared key from standard input and uses it to
determine the sequence of ports to knock.

Usage:
	$0 <host|-c|-d> [rounds]
EOF
	exit
fi

HOST="$1"
ROUNDS=10
PROTOCOL="udp"

if [ -n "${TCP}" ] || echo $0 | fgrep -qi tcp; then
	PROTOCOL="tcp"
fi

if [ -n "$2" ]; then
	ROUNDS="$2"
fi

if [ ${ROUNDS} -gt 32 ]; then
	echo Limiting rounds to 32.
	ROUNDS=32
fi

PORTSTRING=$(sha512sum)

PORTS=()
while [ ${ROUNDS} -gt 0 ]; do
	PORTS+=($((16#$(echo ${PORTSTRING} | cut -c1-4))))
	PORTSTRING=$(echo ${PORTSTRING} | cut -c5-)
	ROUNDS=$((${ROUNDS}-1))
done

if [ "${HOST}" == "-d" ]; then
	echo Port list: ${PORTS[@]}
	exit
fi

if [ "${HOST}" == "-c" ]; then
	PREVLIST=""
	echo "add action=drop chain=input comment=\"Deny access after bogus port knocking attempt\" in-interface-list=WAN log=yes log-prefix=\"Portknock denied from WAN:\" src-address-list=portknock:denied"
	echo "add action=accept chain=input comment=\"Accept SSH after passed port knocking\" dst-port=22 in-interface-list=WAN log=yes log-prefix=\"SSH access from WAN:\" protocol=tcp src-address-list=portknock:passed"
	STEP=${#PORTS[@]}
	while [ ${STEP} -gt 0 ]; do
		if [ "${STEP}" -eq "${#PORTS[@]}" ]; then
			LIST="portknock:passed"
			LOG="log=yes log-prefix=\"Portknock passed:\""
		else
			LIST="portknock:${STEP}"
			LOG=""
		fi
		if [ "${STEP}" -eq 1 ]; then
			PREVLIST=""
		else
			PREVLIST="portknock:$((${STEP}-1))"
		fi
		PORT=${PORTS[$((${STEP}-1))]}
		if [ -n "${PREVLIST}" ]; then
			echo "add action=add-src-to-address-list address-list=portknock:denied src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, block\" dst-port=!${PORT} in-interface-list=WAN protocol=${PROTOCOL}"
			echo "add action=add-src-to-address-list address-list=${LIST} src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, proceed\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
			echo "add action=drop src-address-list=${PREVLIST} chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, finish\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL}"
		else
			echo "add action=add-src-to-address-list address-list=${LIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, proceed\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
			echo "add action=drop chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, finish\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL}"
		fi
		STEP=$((${STEP}-1))
	done
	exit
fi

echo -n Portknocking
for PORT in ${PORTS[@]}; do
	if [ "${PROTOCOL}" == "tcp" ]; then
		#nc -zw 1 ${HOST} ${PORT}
		timeout 0.2 /bin/bash -c "echo '' > /dev/tcp/${HOST}/${PORT}"
	else
		echo "" > /dev/udp/${HOST}/${PORT}
		sleep 0.2
	fi
	echo -n .
done
echo done.
