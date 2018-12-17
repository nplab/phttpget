#!/bin/sh
#export HTTP_USER_AGENT="phttpget yeah!"
#export HTTP_TIMEOUT=1 # seconds!
#export HTTP_TRANSPORT_PROTOCOL=TCP # TCP|SCTP
#export HTTP_SCTP_UDP_ENCAPS_PORT=9899
#export HTTP_DEBUG=LOG_DBG # LOG_PRG|LOG_ERR|LOG_INF|LOG_DBG
#export HTTP_PIPE=NO # use pipes (e.g. for pReplay)
#export HTTP_USE_PIPELINING=NO
#export HTTP_SCTP_MAX_STREAMS=2
#export HTTP_IP_PROTOCOL=0 # 0 = both || 4 = IPv4 || 6 = IPv6

./phttpget bsd3.nplab.de files/4M
