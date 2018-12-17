#!/bin/sh
#export HTTP_USER_AGENT="phttpget yeah!"
#export HTTP_TIMEOUT=1 # seconds!
#export HTTP_TRANSPORT_PROTOCOL=TCP # TCP|SCTP
#export HTTP_SCTP_UDP_ENCAPS_PORT=9899
#export HTTP_USE_PIPELINING=NO
#export HTTP_DEBUG=LOG_INF # LOG_PRG|LOG_ERR|LOG_INF|LOG_DBG
#export HTTP_SCTP_MAX_STREAMS=2
#export HTTP_PIPE=NO # use pipes (e.g. for pReplay)
#export HTTP_IP_PROTOCOL=0 # 0/4/6

REQUEST_FILE=/files/16M
REQUEST_HOST=bsd3.nplab.de
REQUEST_TIMEOUT=20s

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [ "$(uname)" == "Darwin" ]; then
    TIMEOUT_COMMAND='gtimeout'
else
    TIMEOUT_COMMAND='timeout'
fi

runTest(){
    ${TIMEOUT_COMMAND} ${REQUEST_TIMEOUT} "$@"

    local status=$?

    if [ $status -ne 0 ]; then
        printf "${RED}FAIL!${NC}\n\n"
    else
        printf "${GREEN}OK!${NC}\n\n"
    fi
}

export HTTP_IP_PROTOCOL=4
export HTTP_TRANSPORT_PROTOCOL=TCP
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE

export HTTP_IP_PROTOCOL=6
export HTTP_TRANSPORT_PROTOCOL=TCP
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE

export HTTP_IP_PROTOCOL=4
export HTTP_TRANSPORT_PROTOCOL=SCTP
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE

export HTTP_IP_PROTOCOL=6
export HTTP_TRANSPORT_PROTOCOL=SCTP
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE

export HTTP_IP_PROTOCOL=4
export HTTP_TRANSPORT_PROTOCOL=SCTP
export HTTP_SCTP_UDP_ENCAPS_PORT=9899
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE

export HTTP_IP_PROTOCOL=6
export HTTP_TRANSPORT_PROTOCOL=SCTP
export HTTP_SCTP_UDP_ENCAPS_PORT=9899
runTest ./phttpget $REQUEST_HOST $REQUEST_FILE
