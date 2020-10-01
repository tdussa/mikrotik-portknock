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

if echo $0 | fgrep -qi timed; then
	TIMED="yes"
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

if [ -n "${TIMED}" ]; then
	TIMEDPORTSTRING=$(echo -n ${PORTSTRING} | sha512sum | cut -c1-120)$(echo -n ${PORTSTRING} | sha512sum | sha512sum | cut -c1-120)
	TIMEDPORTS=()
	TIMEDPORTSARRAY=""
	MINUTE=0
	while [ -n "${TIMEDPORTSTRING}" ]; do
		PORT=($((16#$(echo ${TIMEDPORTSTRING} | cut -c1-4))))
		TIMEDPORTS+=(${PORT})
		TIMEDPORTSTRING=$(echo ${TIMEDPORTSTRING} | cut -c5-)
		TIMEDPORTSARRAY="${TIMEDPORTSARRAY}\\\"${MINUTE}\\\"=${PORT};"
		MINUTE=$((1+${MINUTE}))
	done
fi

if [ "${HOST}" == "-d" ]; then
	echo Port list: ${PORTS[@]}
	if [ -n "${TIMEDPORTS}" ]; then
		echo Timed port list: ${TIMEDPORTS[@]}
	fi
	exit
fi

if [ "${HOST}" == "-c" ]; then
	PREVLIST=""
	echo "add action=drop chain=input comment=\"Deny access after bogus port knocking attempt\" in-interface-list=WAN log=yes log-prefix=\"Portknock denied from WAN:\" src-address-list=portknock:denied"
	echo "add action=accept chain=input comment=\"Accept SSH after passed port knocking\" dst-port=22 in-interface-list=WAN log=yes log-prefix=\"SSH access from WAN:\" protocol=tcp src-address-list=portknock:passed"
	if [ -n "${TIMED}" ]; then
		LIST="portknock:passed"
		PREVLIST="portknock:timed"
		LOG="log=yes log-prefix=\"Portknock passed:\""
		echo "add action=add-src-to-address-list address-list=${LIST} src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), timed step previous, proceed\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
		echo "add action=drop src-address-list=${PREVLIST} chain=input comment=\"Port knocking (${PROTOCOL}), timed step previous, finish\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL}"
		echo "add action=add-src-to-address-list address-list=${LIST} src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), timed step current, proceed\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
		echo "add action=drop src-address-list=${PREVLIST} chain=input comment=\"Port knocking (${PROTOCOL}), timed step current, finish\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL}"
		echo "add action=add-src-to-address-list address-list=${LIST} src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), timed step next, proceed\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
		echo "add action=drop src-address-list=${PREVLIST} chain=input comment=\"Port knocking (${PROTOCOL}), timed step next, finish\" dst-port=0 in-interface-list=WAN protocol=${PROTOCOL}"
		echo "add action=add-src-to-address-list address-list=portknock:denied src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), timed step, block\" in-interface-list=WAN protocol=${PROTOCOL}"
		LOG=""
	fi
	STEP=${#PORTS[@]}
	while [ ${STEP} -gt 0 ]; do
		if [ "${STEP}" -eq "${#PORTS[@]}" ]; then
			if [ -n "${TIMED}" ]; then
				LIST="portknock:timed"
			else
				LIST="portknock:passed"
				LOG="log=yes log-prefix=\"Portknock passed:\""
			fi
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
			echo "add action=add-src-to-address-list address-list=${LIST} src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, proceed\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
			echo "add action=drop src-address-list=${PREVLIST} chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, finish\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL}"
			echo "add action=add-src-to-address-list address-list=portknock:denied src-address-list=${PREVLIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, block\" in-interface-list=WAN protocol=${PROTOCOL}"
		else
			echo "add action=add-src-to-address-list address-list=${LIST} address-list-timeout=5s chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, proceed\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL} ${LOG}"
			echo "add action=drop chain=input comment=\"Port knocking (${PROTOCOL}), step ${STEP}, finish\" dst-port=${PORT} in-interface-list=WAN protocol=${PROTOCOL}"
		fi
		STEP=$((${STEP}-1))
	done
	if [ -n "${TIMED}" ]; then
		echo "/system script add comment=\"Portknock Timed Step Updater\" dont-require-permissions=no name=PortknockUpdater owner=admin policy=read,write,test source=\"\\
local portlist {${TIMEDPORTSARRAY}}\\
\\nlocal current [:tonum [:pick [/system clock get time] 3 5]]\\
\\nlocal previous ((\\\$current+59) % 60)\\
\\nlocal next ((\\\$current+1) % 60)\\
\\n/ip firewall filter set dst-port=(\\\$portlist->[:tostr \\\$previous]) [/ip firewall filter find comment~\\\"timed step previous\\\"]\\
\\n/ip firewall filter set dst-port=(\\\$portlist->[:tostr \\\$current]) [/ip firewall filter find comment~\\\"timed step current\\\"]\\
\\n/ip firewall filter set dst-port=(\\\$portlist->[:tostr \\\$next]) [/ip firewall filter find comment~\\\"timed step next\\\"]\""
		echo "/system scheduler add comment=\"Portknock Timed Step Updater\" start-time=00:00:00 interval=1m name=PortknockUpdater on-event=PortknockUpdater policy=read,write,test"
	fi
	exit
fi

echo -n Portknocking
for PORT in ${PORTS[@]}; do
	if [ "${PROTOCOL}" == "tcp" ]; then
		timeout 0.2 /bin/bash -c "echo '' > /dev/tcp/${HOST}/${PORT}"
	else
		echo "" > /dev/udp/${HOST}/${PORT}
		sleep 0.2
	fi
	echo -n .
done
if [ -n "${TIMED}" ]; then
	PORT=${TIMEDPORTS[$(date "+%M")]}
	if [ "${PROTOCOL}" == "tcp" ]; then
		timeout 0.2 /bin/bash -c "echo '' > /dev/tcp/${HOST}/${PORT}"
	else
		echo "" > /dev/udp/${HOST}/${PORT}
		sleep 0.2
	fi
	echo -n .
fi
echo done.
