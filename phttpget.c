/*-
 * Copyright 2005, 2016 Colin Percival, Felix Weinrank
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef __linux__
#define _GNU_SOURCE
#define OFF_MAX LONG_MAX
#define _XOPEN_SOURCE 600
#include <sys/select.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>

/* maximum SCTP streams */
#define FIFO_BUFFER_SIZE        1024
#define RESPONSE_BUFFER_SIZE    1048576

#define LOG_PRG             0
#define LOG_ERR             1
#define LOG_INF             2
#define LOG_DBG             3

static const char *     env_HTTP_USER_AGENT;
static char *           env_HTTP_TIMEOUT;
static char *           env_HTTP_TRANSPORT_PROTOCOL;
static char *           env_HTTP_SCTP_UDP_ENCAPS_PORT;
static char *           env_HTTP_DEBUG;
static char *           env_HTTP_PIPE;
static char *           env_HTTP_USE_PIPELINING;
static char *           env_HTTP_SCTP_MAX_STREAMS;
static char *           env_HTTP_IP_PROTOCOL;

static struct timeval   timo = {0, 0};
static uint8_t          log_level = LOG_ERR;                /* 0 = none | 1 = error | 2 = verbose | 3 = very verbose */
static in_port_t        udp_encaps_port = 0;
static int              protocol = IPPROTO_SCTP;
static uint16_t         sctp_num_streams = 0;
static uint8_t          *sctp_stream_status;
static uint32_t         sctp_last_stream = 0;               /* Last SCTP stream read from */
static char             *servername;                        /* Name of server to connect with */
static uint8_t          sctp_streams_busy = 0;              /* Indicator if all streams are busy */
static struct timeval   tv_init;
static uint8_t          use_stdin = 0;                      /* read requests from stdin */
static uint8_t          use_pipe = 0;                       /* read requests from pipe */
static uint8_t          use_pipelining = 1;                 /* allow pipelining */
static uint8_t          save_file = 0;                      /* save received data to file */
static uint16_t         sctp_max_streams = 100;             /* limit number of SCTP streams */
static int              ip_protocol = AF_UNSPEC;            /* 0 = both | 4 = IPv4 | 6 = IPv6 */

/* STATS */
static uint32_t         stat_bytes_header = 0;
static uint32_t         stat_bytes_payload = 0;
static uint32_t         stat_status_200 = 0;
static uint32_t         stat_status_404 = 0;
static uint32_t         stat_status_other = 0;


int fifo_in_fd = -1;
int fifo_out_fd = -1;
char *fifo_in_name = "/tmp/phttpget-in";
char *fifo_out_name = "/tmp/phttpget-out";

enum stream_status {STREAM_FREE, STREAM_USED};

struct sctp_pipe_data {
    uint32_t    id;
    uint32_t    path_len;
    uint32_t    cookie_len;
    uint32_t    header_len;
    uint32_t    payload_len;
    char        path[FIFO_BUFFER_SIZE];
} __attribute__ ((packed));

struct request {
    uint32_t                id;
    char                    *cookie;
    char                    *url;
    struct sctp_pipe_data   pipe_data;
    TAILQ_ENTRY(request)    entries;
};

TAILQ_HEAD(request_queue, request);

struct request_queue requests_open;
struct request_queue requests_pending;

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))

#ifndef __FreeBSD__
/* Locate a substring in a string */
char *
strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}
#endif

/*
 * Write log entry
 */
static void
mylog(uint8_t level, const char* format, ...)
{

    struct timeval tv_now, tv_diff;
    // skip unwanted loglevels
    if (log_level < level) {
        return;
    }

    gettimeofday(&tv_now, NULL);

    tv_diff.tv_sec = tv_now.tv_sec - tv_init.tv_sec;

    if (tv_init.tv_usec < tv_now.tv_usec) {
        tv_diff.tv_usec = tv_now.tv_usec - tv_init.tv_usec;
    } else {
        tv_diff.tv_sec -= 1;
        tv_diff.tv_usec = 1000000 + tv_now.tv_usec - tv_init.tv_usec;
    }

    fprintf(stderr, "[%4ld.%06ld]", (long)tv_diff.tv_sec, (long)tv_diff.tv_usec);

    switch (level) {
        case 0:
            fprintf(stderr, "[PRG] ");
            break;
        case 1:
            fprintf(stderr, "[ERR] ");
            break;
        case 2:
            fprintf(stderr, "[INF] ");
            break;
        case 3:
            fprintf(stderr, "[DBG] ");
            break;
    }

    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);

    fprintf(stderr, "\n"); // xxx:ugly solution...
}

/* Print usage and exit */
static void
usage(void)
{
    mylog(LOG_PRG, "usage: phttpget server [file1 file2 filnen]\n");
    exit(EX_USAGE);
}

/* Read environment variables */
static void
readenv(void)
{
    char *p;
    long http_timeout;
    long port;
    long sctp_max_streams_temp;
    long ip_protocol_temp;

    env_HTTP_USER_AGENT = getenv("HTTP_USER_AGENT");
    if (env_HTTP_USER_AGENT == NULL) {
        env_HTTP_USER_AGENT = "phttpget/0.2";
    }

    env_HTTP_TIMEOUT = getenv("HTTP_TIMEOUT");
    if (env_HTTP_TIMEOUT != NULL) {
        http_timeout = strtol(env_HTTP_TIMEOUT, &p, 10);
        if ((*env_HTTP_TIMEOUT == '\0') || (*p != '\0') || (http_timeout < 0)) {
            mylog(LOG_ERR, "HTTP_TIMEOUT (%s) is not a positive integer", env_HTTP_TIMEOUT);
            exit(EXIT_FAILURE);
        } else {
            timo.tv_sec = http_timeout;
        }
    }
    mylog(LOG_PRG, "Settings - timeout : %d", timo.tv_sec);

    env_HTTP_TRANSPORT_PROTOCOL = getenv("HTTP_TRANSPORT_PROTOCOL");
    if (env_HTTP_TRANSPORT_PROTOCOL != NULL) {
        if (strncasecmp(env_HTTP_TRANSPORT_PROTOCOL, "TCP", 3) == 0) {
            protocol = IPPROTO_TCP;
        } else if (strncasecmp(env_HTTP_TRANSPORT_PROTOCOL, "SCTP", 4) == 0) {
            protocol = IPPROTO_SCTP;
        } else {
            mylog(LOG_ERR, "HTTP_TRANSPORT_PROTOCOL (%s) not supported", env_HTTP_TRANSPORT_PROTOCOL);
            exit(EXIT_FAILURE);
        }
    }
    mylog(LOG_PRG, "Settings - protocol : %s", (protocol == IPPROTO_TCP) ? "TCP" : "SCTP");

    env_HTTP_SCTP_UDP_ENCAPS_PORT = getenv("HTTP_SCTP_UDP_ENCAPS_PORT");
    if (env_HTTP_SCTP_UDP_ENCAPS_PORT != NULL) {
        port = strtol(env_HTTP_SCTP_UDP_ENCAPS_PORT, &p, 10);
        if ((*env_HTTP_SCTP_UDP_ENCAPS_PORT == '\0') || (*p != '\0') || (port < 0) || (port > 65535)) {
            mylog(LOG_ERR, "HTTP_SCTP_UDP_ENCAPS_PORT (%s) is not a valid port number", env_HTTP_SCTP_UDP_ENCAPS_PORT);
            exit(EXIT_FAILURE);
        } else {
            udp_encaps_port = (in_port_t)port;
        }
    }

    env_HTTP_DEBUG = getenv("HTTP_DEBUG");
    if (env_HTTP_DEBUG != NULL) {
        if (strncasecmp(env_HTTP_DEBUG, "LOG_PRG", 7) == 0) {
            log_level = LOG_PRG;
        } else if (strncasecmp(env_HTTP_DEBUG, "LOG_ERR", 7) == 0) {
            log_level = LOG_ERR;
        } else if (strncasecmp(env_HTTP_DEBUG, "LOG_INF", 7) == 0) {
            log_level = LOG_INF;
        } else if (strncasecmp(env_HTTP_DEBUG, "LOG_DBG", 7) == 0) {
            log_level = LOG_DBG;
        } else {
            mylog(LOG_ERR, "unknown debug level");
            exit(EXIT_FAILURE);
        }
    }

    env_HTTP_PIPE = getenv("HTTP_PIPE");
    if (env_HTTP_PIPE != NULL) {
        use_pipe = 1;
        mylog(LOG_INF, "Using pipes for requests/reposnses");
    }

    env_HTTP_USE_PIPELINING = getenv("HTTP_USE_PIPELINING");
    if (env_HTTP_USE_PIPELINING != NULL) {
        if (strncasecmp(env_HTTP_USE_PIPELINING, "YES", 3) == 0) {
            use_pipelining = 1;
        } else if (strncasecmp(env_HTTP_USE_PIPELINING, "NO", 2) == 0) {
            use_pipelining = 0;
        } else {
            mylog(LOG_ERR, "invalid settings for pipelining support");
            exit(EXIT_FAILURE);
        }
    }
    mylog(LOG_PRG, "Settings - pipelining : %s", (use_pipelining == 1) ? "enabled" : "disabled");

    env_HTTP_SCTP_MAX_STREAMS = getenv("HTTP_SCTP_MAX_STREAMS");
    if (env_HTTP_SCTP_MAX_STREAMS != NULL) {
        sctp_max_streams_temp = strtol(env_HTTP_SCTP_MAX_STREAMS, NULL, 10);
        if (sctp_max_streams_temp < 1 || sctp_max_streams_temp > 65536) {
            mylog(LOG_ERR, "sctp_max_streams out of range");
            exit(EXIT_FAILURE);
        }
        sctp_max_streams = (uint16_t) sctp_max_streams_temp;
    }

    env_HTTP_IP_PROTOCOL = getenv("HTTP_IP_PROTOCOL");
    if (env_HTTP_IP_PROTOCOL != NULL) {
        ip_protocol_temp = strtol(env_HTTP_IP_PROTOCOL, NULL, 10);

        switch (ip_protocol_temp) {
            case 0:
                ip_protocol = AF_UNSPEC;
                mylog(LOG_PRG, "Settings - ip_protocol : AF_UNSPEC");
                break;
            case 4:
                ip_protocol = AF_INET;
                mylog(LOG_PRG, "Settings - ip_protocol : AF_INET");
                break;
            case 6:
                ip_protocol = AF_INET6;
                mylog(LOG_PRG, "Settings - ip_protocol : AF_INET6");
                break;
            default:
                mylog(LOG_ERR, "ip_protocol out of range - shoud be 0/4/6");
                exit(EXIT_FAILURE);
        }



    }

    if (protocol == IPPROTO_SCTP && use_pipelining) {
        mylog(LOG_PRG, "Settings - max SCTP streams : %d", sctp_max_streams);
    }
}

static int
setup_connection(struct addrinfo *res, int *sd) {
    int i = 0;
    struct sctp_initmsg initmsg;    /* To signal die number of incoming and outgoing streams */
    int val;                        /* Value used for setsockopt call */
    struct sctp_status status;      /* To reuest SCTP status information */
#ifdef SCTP_REMOTE_UDP_ENCAPS_PORT
    struct sctp_udpencaps encaps;   /* SCTP/UDP information */
#endif
#ifdef __linux__
    struct sctp_event_subscribe subscribe;
#endif
    socklen_t statuslen = 0;

    /* No addresses left to try :-( */
    if (res == NULL) {
        mylog(LOG_ERR, "[%d][%s] - Could not connect to %s", __LINE__, __func__, servername);
        exit(EXIT_FAILURE);
    }

    char addr_str[INET6_ADDRSTRLEN];
    struct sockaddr_in* saddr = (struct sockaddr_in*)res->ai_addr;
    struct sockaddr_in6* saddr6 = (struct sockaddr_in6*)res->ai_addr;

    if (res->ai_family == AF_INET) {
        inet_ntop(res->ai_family, &saddr->sin_addr, addr_str, sizeof(addr_str));
    } else if (res->ai_family == AF_INET6) {
        inet_ntop(res->ai_family, &saddr6->sin6_addr, addr_str, sizeof(addr_str));
    } else {
        mylog(LOG_ERR, "[%d][%s] - Unsupported address family", __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    mylog(LOG_PRG, "[%d][%s] - Candidate : %s %d", __LINE__, __func__, addr_str , res->ai_family);


    if (res->ai_family == AF_INET || res->ai_family == AF_INET6) {
        mylog(LOG_PRG, "[%d][%s] - Using IPv%d", __LINE__, __func__, (res->ai_family == AF_INET) ? (4) : (6));
    } else {
        mylog(LOG_ERR, "[%d][%s] - unknown address family", __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    /* Create a socket... */
    *sd = socket(res->ai_family, res->ai_socktype, protocol);
    if (*sd == -1) {
        /* reatry... */
        mylog(LOG_ERR, "[%d][%s] - socket() failed", __LINE__, __func__);
        return -1;
    }

    /* ... set timeouts ... */
    setsockopt(*sd, SOL_SOCKET, SO_SNDTIMEO, (void *)&timo, (socklen_t)sizeof(timo));
    setsockopt(*sd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timo, (socklen_t)sizeof(timo));

    /* set SCTP specific options */
    if (protocol == IPPROTO_SCTP) {
        /* Ensure an appropriate number of stream will be negotated. */
        initmsg.sinit_num_ostreams = sctp_max_streams;
        initmsg.sinit_max_instreams = sctp_max_streams;
        initmsg.sinit_max_attempts = 0;   /* Use default */
        initmsg.sinit_max_init_timeo = 0; /* Use default */
        if (setsockopt(*sd, IPPROTO_SCTP, SCTP_INITMSG, (char*) &initmsg, sizeof(initmsg)) < 0) {
            mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        val = 1;

        if (setsockopt(*sd, IPPROTO_SCTP, SCTP_NODELAY, (char*) &val, sizeof(val)) < 0) {
            mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

#if defined(__FreeBSD__) || defined(__APPLE__)
        /* Enable RCVINFO delivery */
        if (setsockopt(*sd, IPPROTO_SCTP, SCTP_RECVRCVINFO, (char*) &val, sizeof(val)) < 0) {
            mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }
#elif defined(__linux__)
        /* sorry michael ... i know this must hurt you! :) */
        memset(&subscribe, 0, sizeof(subscribe));
        subscribe.sctp_data_io_event = val;
        /* subscribe.sctp_association_event = val; */
        if (setsockopt(*sd, SOL_SCTP, SCTP_EVENTS, (char *)&subscribe, sizeof(subscribe)) < 0) {
            mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }
#endif
        if (udp_encaps_port > 0) {
#ifdef SCTP_REMOTE_UDP_ENCAPS_PORT
            /* Use UDP encapsulation for SCTP */
            memset(&encaps, 0, sizeof(encaps));
            encaps.sue_address.ss_family = res->ai_family;
            encaps.sue_address.ss_len = res->ai_addrlen;
            encaps.sue_port = htons(udp_encaps_port);
            if (setsockopt(*sd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (void *)&encaps, (socklen_t)sizeof(encaps))) {
                mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }
            mylog(LOG_PRG, "Settings - UDP encapsulation port : %d", udp_encaps_port);
#else
            mylog(LOG_ERR, "[%d][%s] - UDP encapsulation unsupported", __LINE__, __func__);
            exit(EXIT_FAILURE);
#endif
}
    }

#ifdef SO_NOSIGPIPE
    /* ... disable SIGPIPE generation ... */
    val = 1;
    setsockopt(*sd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(int));
#endif

    /* ... and connect to the server. */
    if (connect(*sd, res->ai_addr, res->ai_addrlen)) {
        close(*sd);
        *sd = -1;
        mylog(LOG_ERR, "[%d][%s] - connect() failed", __LINE__, __func__);
        return -1;
    }

    if (protocol == IPPROTO_SCTP) {
        /* Get the actual number of outgoing streams. */
        statuslen = sizeof(status);
        memset(&status, 0, sizeof(status));
        if (getsockopt(*sd, IPPROTO_SCTP, SCTP_STATUS, &status, &statuslen) < 0) {
            mylog(LOG_ERR, "[%d][%s] - setsockopt() failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        sctp_num_streams = MIN(status.sstat_instrms, status.sstat_outstrms);

        /* Allocate stream status array */
        if ((sctp_stream_status = malloc(sizeof(uint8_t) * sctp_num_streams)) == NULL) {
            mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        /* Initialize the stream status array */
        for (i = 0; i < sctp_num_streams; i++) {
            sctp_stream_status[i] = STREAM_FREE;
        }

        mylog(LOG_INF, "[%d][%s] - SCTP available Streams: %d IN - %d OUT - using: %d", __LINE__, __func__, status.sstat_instrms, status.sstat_outstrms, sctp_num_streams);
    }


    mylog(LOG_INF, "[%d][%s] - connected", __LINE__, __func__);
    return 0;
}

static int
readln(int sd, char *resbuf, int *resbuflen, int *resbufpos)
{
    ssize_t len = 0;
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *scmsg;
#if defined(__FreeBSD__) || defined(__APPLE__)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
    struct sctp_rcvinfo *rcvinfo;
    memset(cmsgbuf, 0, CMSG_SPACE(sizeof(struct sctp_rcvinfo)));
#elif defined(__linux__)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *rcvinfo;
    memset(cmsgbuf, 0, CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)));
#endif

    while (strnstr(resbuf + *resbufpos, "\r\n", *resbuflen - *resbufpos) == NULL) {
        /* Move buffered data to the start of the buffer */
        if (*resbufpos != 0) {
            memmove(resbuf, resbuf + *resbufpos, *resbuflen - *resbufpos);
            *resbuflen -= *resbufpos;
            *resbufpos = 0;
        }

        /* If the buffer is full, complain */
        if (*resbuflen == RESPONSE_BUFFER_SIZE) {
            mylog(LOG_INF, "[%d][%s] - buffer is full", __LINE__, __func__);
            exit(EXIT_FAILURE);
            return -1;
        }

        /* message orientated protocol - new message : new response */
        if (protocol == IPPROTO_SCTP) {
            *resbuflen = 0;
            *resbufpos = 0;
        }

        /* Read more data into the buffer */
        iov.iov_base = resbuf + *resbuflen;
        iov.iov_len = RESPONSE_BUFFER_SIZE - *resbuflen;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        len = recvmsg(sd, &msg, 0);

        if ((MSG_NOTIFICATION & msg.msg_flags)) {
            mylog(LOG_ERR, "[%d][%s] - recvmsg - got notification - fixme", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        /* If recvmsg returned 0 or -1 (no interrupt) - we stop reading */
        if ((len == 0) || ((len == -1) && (errno != EINTR))) {
            mylog(LOG_ERR, "[%d][%s] - recvmsg returned %d - %s", __LINE__, __func__, len, strerror(errno));
            return -1;
        } else if (len > 0) {
            *resbuflen += len;
        }

        if (protocol == IPPROTO_SCTP) {
            /* Stream we received data from */
            scmsg = CMSG_FIRSTHDR(&msg);
            if (scmsg == NULL) {
                mylog(LOG_ERR, "[%d][%s] - CMSG_FIRSTHDR() failed - len %d", __LINE__, __func__, len);
                exit(EXIT_FAILURE);
            }

#if defined(__FreeBSD__) || defined(__APPLE__)
            rcvinfo = (struct sctp_rcvinfo *)CMSG_DATA(scmsg);
            sctp_last_stream = rcvinfo->rcv_sid;
#elif defined(__linux__)
            rcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(scmsg);
            sctp_last_stream = rcvinfo->sinfo_stream;
#endif

        }

    }

    return 0;
}

/* Copy bytes from one sd fd to sd fd */
static int
copybytes(int sd, int fd, off_t copylen, char *resbuf, int *resbuflen, int *resbufpos)
{
    ssize_t len;
    struct msghdr msg;
    struct iovec iov;
#if defined(__FreeBSD__) || defined(__APPLE__)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
    memset(cmsgbuf, 0, CMSG_SPACE(sizeof(struct sctp_rcvinfo)));
#elif defined(__linux__)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    memset(cmsgbuf, 0, CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)));
#endif

    while (copylen) {
        /* Write data from resbuf to fd */
        len = *resbuflen - *resbufpos;
        if (copylen < len) {
            len = copylen;
        }

        /* Write to file until resbuf is "empty" before calling recvmsg */
        if (len > 0) {
            /* fd is unset so we just discard data */
            if (fd == -1) {
                mylog(LOG_DBG, "[%d][%s] - fd == -1 - discarding", __LINE__, __func__);
            /* we have valid fd - so write to file */
            } else if ((len = write(fd, resbuf + *resbufpos, len)) == -1) {
                mylog(LOG_ERR, "[%d][%s] - write() failed - fix it!", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }

            *resbufpos += len;
            copylen -= len;
            stat_bytes_payload += len;
            continue;
        }

        iov.iov_base = resbuf;
        iov.iov_len = RESPONSE_BUFFER_SIZE;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        /* Read more data into buffer */
        if ((len = recvmsg(sd, &msg, 0)) == -1) {
            if (errno == EINTR) {
                continue;
            }
            mylog(LOG_ERR, "[%d][%s] - recvmsg() failed : %s", __LINE__, __func__, strerror(errno));
            return -1;
        } else if (len == 0) {
            mylog(LOG_ERR, "[%d][%s] - recvmsg() returned 0", __LINE__, __func__);
            return -2;
        } else {
            mylog(LOG_DBG, "[%d][%s] - read %d bytes ", __LINE__, __func__, len);
            *resbuflen = len;
            *resbufpos = 0;
        }
    }

    return 0;
}

static int
send_request(int sd,  char *reqbuf, int *reqbuflen, int *reqbufpos) {
#if defined(__FreeBSD__) || defined(__APPLE__)
    char* cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct sctp_sndinfo *sndinfo;
#elif defined(__linux__)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *sndinfo;
#endif
    struct iovec iov;
    struct msghdr msghdr;

    struct cmsghdr *cmsg;
    int len;
    int i;

    /* initialize */
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    memset(&msghdr, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct iovec));

    msghdr.msg_iov = &iov;
    msghdr.msg_iovlen = 1;

    mylog(LOG_DBG, "[%d][%s] - %s", __LINE__, __func__, reqbuf + *reqbufpos);

    /* if using SCTP, append control msg to define outgoing stream */
    if (protocol == IPPROTO_SCTP) {
        msghdr.msg_control = cmsgbuf;
        msghdr.msg_controllen = sizeof(cmsgbuf);

        cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = IPPROTO_SCTP;
        cmsg->cmsg_len = sizeof(cmsgbuf);
#if defined(__FreeBSD__) || defined(__APPLE__)
        cmsg->cmsg_type = SCTP_SNDINFO;
        sndinfo = (struct sctp_sndinfo*) CMSG_DATA(cmsg);
#elif defined(__linux__)
        cmsg->cmsg_type = SCTP_SNDRCV;
        sndinfo = (struct sctp_sndrcvinfo*) CMSG_DATA(cmsg);
#endif


        sctp_streams_busy = 1;

        /* lookup next free stream - if all streams busy return with -2 */
        for (i = 0; i < sctp_num_streams; i++) {
            if (sctp_stream_status[i] == STREAM_FREE) {
                sctp_stream_status[i] = STREAM_USED;
#if defined(__FreeBSD__) || defined(__APPLE__)
                sndinfo->snd_sid = i;
#elif defined(__linux__)
                sndinfo->sinfo_stream = i;
#endif
                sctp_streams_busy = 0;
                break;
            }
        }

        if (sctp_streams_busy == 1) {
            mylog(LOG_INF, "[%d][%s] - all SCTP streams are busy...", __LINE__, __func__);
            return 0;
        }
    }

    /* send until we reached the end of the buffer... */
    while (*reqbufpos < *reqbuflen) {
        iov.iov_base = reqbuf + *reqbufpos;
        iov.iov_len = *reqbuflen - *reqbufpos;

        len = sendmsg(sd, &msghdr, 0);

        /* sendmsg failed - but don't worry - non-blocking :) */
        if (len == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                mylog(LOG_DBG, "[%d][%s] - sendmsg() failed - EWOULDBLOCK", __LINE__, __func__);
                break;
            } else {
                return -1;
            }
        }

        /* move reqbufpos by sent bytes */
        *reqbufpos += len;
    }

    return 0;
}

static int
handle_response(int *sd, int *fd, char *resbuf, int *resbuflen, int *resbufpos, struct request *request, int *keepalive, int *pipelined)
{
    int error = 0;
    char * hln;                 /* Pointer within header line */
    char * eolp;                /* Pointer to "\r\n" within resbuf */
    int statuscode = 0;         /* HTTP Status code */
    off_t contentlength = -1;   /* Value from Content-Length header */
    int chunked = 0;            /* != if transfer-encoding is chunked */
    off_t clen;                 /* Chunk length */
    char * fname = NULL;        /* Name of downloaded file */
    uint32_t bytes_header_tmp = stat_bytes_header;
    uint32_t bytes_payload_tmp = stat_bytes_payload;
    int len = 0;
    int len_left = 0;
    char * bufptr = NULL;

    *keepalive = 0;

    if (protocol == IPPROTO_SCTP) {
        *resbufpos = 0;
        *resbuflen = 0;

        /* Get a header line - only once for SCTP */
        if (readln(*sd, resbuf, resbuflen, resbufpos)) {
            mylog(LOG_ERR, "[%d][%s] - readln() failed", __LINE__, __func__);
            return -1;
        }
    }

    do {
        if (protocol == IPPROTO_TCP) {
            /* Get a header line - stream based TCP*/
            if (readln(*sd, resbuf, resbuflen, resbufpos)) {
                mylog(LOG_ERR, "[%d][%s] - readln() failed", __LINE__, __func__);
                return -1;
            }
        }

        hln = resbuf + *resbufpos;
        eolp = strnstr(hln, "\r\n", *resbuflen - *resbufpos);
        *resbufpos = (eolp - resbuf) + 2;
        *eolp = '\0';

        stat_bytes_header += strlen(hln) + 2;

        mylog(LOG_DBG, "[%d][%s] - %s", __LINE__, __func__, hln);

        /* Make sure it doesn't contain a NUL character */
        if (strchr(hln, '\0') != eolp) {
            return -1;
        }

        if (statuscode == 0) {
            /* The first line MUST be HTTP/1.x xxx ... */
            if ((strncmp(hln, "HTTP/1.", 7) != 0) || !isdigit(hln[7])) {
                return -1;
            }

            /*
             * If the minor version number isn't zero,
             * then we can assume that pipelining our
             * requests is OK -- as long as we don't
             * see a "Connection: close" line later
             * and we either have a Content-Length or
             * Transfer-Encoding: chunked header to
             * tell us the length.
             */
            if (hln[7] != '0' && use_pipelining) {
                *pipelined = 1;
            }

            /* Skip over the minor version number */
            hln = strchr(hln + 7, ' ');
            if (hln == NULL) {
                return -1;
            } else {
                hln++;
            }

            /* Read the status code */
            while (isdigit(*hln)) {
                statuscode = statuscode * 10 + *hln - '0';
                hln++;
            }

            if (statuscode < 100 || statuscode > 599) {
                return -1;
            }

            /* Ignore the rest of the line */
            continue;
        }

        /* Check for "Connection: close" or "Connection: Keep-Alive" header */
        if (strncasecmp(hln, "Connection:", 11) == 0) {
            hln += 11;
            if (strcasestr(hln, "close") != NULL) {
                *pipelined = 0;
            }

            if (strcasestr(hln, "Keep-Alive") != NULL) {
                *keepalive = 1;
            }

            mylog(LOG_DBG, "[%d][%s] - Keep-Alive : %d - Pipelined : %d", __LINE__, __func__, *keepalive, *pipelined);

            /* Next header... */
            continue;
        }

        /* Check for "Content-Length:" header */
        if (strncasecmp(hln, "Content-Length:", 15) == 0) {
            hln += 15;
            contentlength = 0;

            /* Find the start of the length */
            while (!isdigit(*hln) && (*hln != '\0')) {
                hln++;
            }

            /* Compute the length */
            while (isdigit(*hln)) {
                if (contentlength >= OFF_MAX / 10) {
                    /* Nasty people... */
                    return -1;
                }
                contentlength = contentlength * 10 + *hln - '0';
                hln++;
            }

            /* Next header... */
            continue;
        }

        /* Check for "Transfer-Encoding: chunked" header */
        if (strncasecmp(hln, "Transfer-Encoding:", 18) == 0) {
            hln += 18;
            if (strcasestr(hln, "chunked") != NULL) {
                chunked = 1;
            }

            /* Next header... */
            continue;
        }

        /* We blithely ignore any other header lines */

        /* No more header lines */
        if (strlen(hln) == 0) {
            /*
             * If the status code was 1xx, then there will
             * be a real header later.  Servers may emit
             * 1xx header blocks at will, but since we
             * don't expect one, we should just ignore it.
             */
            if (100 <= statuscode && statuscode <= 199) {
                statuscode = 0;
                continue;
            }

            /* End of header; message body follows */
            break;
        }
    } while (1);

    /* No message body for 204 or 304 */
    if (statuscode == 204 || statuscode == 304) {
        return 0;
    }

    /*
     * There should be a message body coming, but we only want
     * to send it to a file if the status code is 200
     */
    if (statuscode == 200 && save_file == 1) {
        /* Generate a file name for the download */
        fname = strrchr(request->url, '/');
        if (fname == NULL) {
            fname = request->url;
        } else {
            fname++;
        }

        if (strlen(fname) == 0) {
            mylog(LOG_ERR, "[%d][%s] - Cannot optain file name", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        /* Open file for writing */
        if ((*fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
            mylog(LOG_ERR, "[%d][%s] - Failed to open file for writing", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }
    };
    /* Read the message and send data to fd if appropriate */
    if (chunked) {
        /* Handle a chunked-encoded entity */

        /* Read chunks */
        do {
            error = readln(*sd, resbuf, resbuflen, resbufpos);
            if (error) {
                return -1;
            }
            hln = resbuf + *resbufpos;
            eolp = strstr(hln, "\r\n");
            *resbufpos = (eolp - resbuf) + 2;

            clen = 0;
            while (isxdigit(*hln)) {
                if (clen >= OFF_MAX / 16) {
                    /* Nasty people... */
                    return -1;
                }

                if (isdigit(*hln)) {
                    clen = clen * 16 + *hln - '0';
                } else {
                    clen = clen * 16 + 10 + tolower(*hln) - 'a';
                }
                hln++;
            }

            if (copybytes(*sd, *fd, clen, resbuf, resbuflen, resbufpos)) {
                mylog(LOG_ERR, "[%d][%s] - copybytes failed", __LINE__, __func__);
                *keepalive = 0;
                return -1;
            }
        } while (clen != 0);

        /* Read trailer and final CRLF */
        do {
            error = readln(*sd, resbuf, resbuflen, resbufpos);
            if (error) {
                return -1;
            }
            hln = resbuf + *resbufpos;
            eolp = strstr(hln, "\r\n");
            *resbufpos = (eolp - resbuf) + 2;
        } while (hln != eolp);
    } else if (contentlength != -1 || protocol == IPPROTO_SCTP) {
        if (copybytes(*sd, *fd, contentlength, resbuf, resbuflen, resbufpos)) {
            mylog(LOG_ERR, "[%d][%s] - copybytes failed", __LINE__, __func__);
            *keepalive = 0;
            //return -1;
        }
    } else {

        /*
         * Not chunked, and no content length header.
         * Read everything until the server closes the
         * socket.
         */
        if (copybytes(*sd, *fd, OFF_MAX, resbuf, resbuflen, resbufpos)) {
            mylog(LOG_ERR, "[%d][%s] - copybytes failed", __LINE__, __func__);
            *keepalive = 0;
            //return -1;
        }
        *pipelined = 0;
    }

    /* close filedescriptor if open */
    if (*fd != -1) {
        close(*fd);
        *fd = -1;
    }


    /* status stats */
    switch (statuscode) {
        case 200:
            stat_status_200++;
            break;
        case 404:
            stat_status_404++;
            break;
        default:
            stat_status_other++;
            break;
    }

    mylog(LOG_INF, "#####################");
    if (protocol == IPPROTO_SCTP) {
        mylog(LOG_PRG, "#%d - %d - %s - sctp sid: %d", stat_status_200 + stat_status_404 + stat_status_other, statuscode, request->url, sctp_last_stream);
    } else {
        mylog(LOG_PRG, "#%d - %d - %s", stat_status_200 + stat_status_404 + stat_status_other, statuscode, request->url);
    }
    mylog(LOG_INF, "\t HEADER   : %d", stat_bytes_header - bytes_header_tmp);
    mylog(LOG_INF, "\t PAYLOAD  : %d", stat_bytes_payload - bytes_payload_tmp);
    mylog(LOG_INF, "#####################");

    /* write response to pipe */
    if (use_pipe) {
        if ((request = TAILQ_FIRST(&requests_pending)) != NULL) {
            request->pipe_data.header_len = stat_bytes_header - bytes_header_tmp;
            request->pipe_data.payload_len = stat_bytes_payload - bytes_payload_tmp;

            len_left = sizeof(struct sctp_pipe_data);
            bufptr = (char *) &(request->pipe_data);
            while (len_left > 0) {
                len = write(fifo_out_fd, bufptr + sizeof(struct sctp_pipe_data) - len_left, len_left);
                mylog(LOG_DBG, "[%d][%s] - fifo write : %d byte", __LINE__, __func__, len);
                if (len == -1 || len == 0) {
                    mylog(LOG_ERR, "[%d][%s] - fifo write failed: %d - %s", __LINE__, __func__, errno, strerror(errno));
                }

                len_left -= len;
            }
        }
    }

    return 0;
}


int
main(int argc, char *argv[])
{
    struct addrinfo hints;          /* Hints to getaddrinfo */
    struct addrinfo *res;           /* Pointer to server address being used */
    struct addrinfo *res0;          /* Pointer to server addresses */
    char * reqbuf = NULL;           /* Request buffer */
    int reqbufpos = 0;              /* Request buffer position */
    int reqbuflen = 0;              /* Request buffer length */
    int pipelined = 0;              /* != 0 if connection in pipelined mode. */
    int sd = -1;                    /* Socket descriptor */
    int sdflags = 0;                /* Flags on the socket sd */
    int error;                      /* Error code */
    int i = 0;                      /* For loop iterator */
    char *resbuf = NULL;            /* Response buffer */
    int resbuflen = 0;              /* Length of the receiver buffer */
    int keepalive = 0;              /* Keep-Alive indicator */
    int fd = -1;                    /* Filedescriptor (file) */
    struct request *request;        /* Request from open or pending queue */
    int resbufpos = 0;              /* Response buffer position */
    int num_req_open = 0;
    int num_req_pending = 0;
    int num_req_finished = 0;
    fd_set fdsetrecv;
    fd_set fdsetsend;
    int maxfd = 0;
    int selectsock = -1;
    int len = 0;
    int len_left = 0;
    uint8_t num_req = 0;
    char *bufptr = NULL;

    /* Initialize open (unsent) requests and pending requests queues */
    TAILQ_INIT(&requests_open);
    TAILQ_INIT(&requests_pending);

    gettimeofday(&tv_init, NULL);

    /* Check that the arguments are sensible */
    if (argc < 2) {
        usage();
    }

    /* Read important environment variables */
    readenv();

    /* Get server name and adjust arg[cv] to point at file names */
    servername = argv[1];

    /* Allocate response buffer */
    if ((resbuf = malloc(RESPONSE_BUFFER_SIZE)) == NULL) {
        mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
    }

    /* Server lookup */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ip_protocol;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
#ifdef __FreeBSD__
    error = getaddrinfo(servername, "http", &hints, &res0);
#else
    /* Not all OSes have an SCTP entry for HTTP in /etc/services yet. */
    error = getaddrinfo(servername, "80", &hints, &res0);
#endif
    if (error) {
        mylog(LOG_ERR, "[%d][%s] - host = %s, port = %s: %s", __LINE__, __func__, servername, "http", gai_strerror(error));
        exit(EXIT_FAILURE);
    }
    if (res0 == NULL) {
        mylog(LOG_ERR, "[%d][%s] - lookup for %s failed", __LINE__, __func__, servername);
        exit(EXIT_FAILURE);
    }
    res = res0;

    /* setup connection before waiting for fifo */
    //setup_connection(res, &sd);

    if (argc < 3) {
        if (use_pipe) {
            mylog(LOG_PRG, "interactive mode - reading from PIPE");
            mkfifo(fifo_out_name, 0666);
            mkfifo(fifo_in_name, 0666);
            fifo_in_fd = open(fifo_in_name, O_RDONLY);
            fifo_out_fd = open(fifo_out_name, O_WRONLY);
        } else {
            use_stdin = 1;
            mylog(LOG_PRG, "interactive mode - reading from STDIN");
        }
    } else {
        /* Parse requests by cmdline arguments and queue them */
        for (i = 2; i < argc; i++) {
            if ((request = malloc(sizeof(struct request))) == NULL) {
                mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }
            num_req++;
            request->id = num_req;
            request->url = argv[i];
            request->cookie = NULL;
            mylog(LOG_INF, "[%d][%s] - queueing : %s", __LINE__, __func__, request->url);
            TAILQ_INSERT_TAIL(&requests_open, request, entries);
            num_req_open++;
        }

        mylog(LOG_INF, "[%d][%s] - %d requests open", __LINE__, __func__, num_req_open);
    }

    /* Do the fetching */
    while (num_req_open > 0 || num_req_pending > 0 || use_pipe || use_stdin) {

        /* Make sure we have a connected socket */
        for (; sd == -1; res = res->ai_next) {
            setup_connection(res, &sd);
        }

        if (sd == -1) {
            mylog(LOG_ERR, "[%d][%s] - no transport connection!", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        /* Initialize select structs */
        FD_ZERO(&fdsetrecv);
        FD_ZERO(&fdsetsend);

        /* Hook stdin or pipe for select if we are interactive */
        if (use_pipe) {
                FD_SET(fifo_in_fd, &fdsetrecv);
        } else if (use_stdin) {
                FD_SET(STDIN_FILENO, &fdsetrecv);
        }

        /* Bind sd to select functions - if we have requests open, hook for sending ... */
        if (num_req_open > 0) {
            FD_SET(sd, &fdsetsend);
        }
        /* ... and always for receiving */
        FD_SET(sd, &fdsetrecv);

        if (use_pipe) {
            maxfd = MAX(sd, fifo_in_fd) + 1;
        } else if (use_stdin) {
            maxfd = MAX(sd, STDIN_FILENO) + 1;
        } else {
            maxfd = sd + 1;
        }

        /* Select section - handle stdin and socket */
        if ((selectsock = select(maxfd, &fdsetrecv, &fdsetsend, NULL, NULL)) < 0) {
            mylog(LOG_ERR, "[%d][%s] - select failed", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

        /* Ready to read a new request from stdin */
        if (use_stdin && FD_ISSET(STDIN_FILENO, &fdsetrecv)) {
            mylog(LOG_DBG, "[%d][%s] - select for STDIN", __LINE__, __func__);

            if ((request = malloc(sizeof(struct request))) == NULL) {
                mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }

            if ((request->url = malloc(BUFSIZ)) == NULL) {
                mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }

            if (fgets(request->url, BUFSIZ, stdin) == NULL) {
                mylog(LOG_ERR, "[%d][%s] - fgets failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            } else {
                num_req++;
                request->id = num_req;
                request->url[strcspn(request->url, "\n")] = 0;
                request->cookie = NULL;
                TAILQ_INSERT_TAIL(&requests_open, request, entries);
                num_req_open++;

                mylog(LOG_INF, "[%d][%s] - queueing : %s", __LINE__, __func__, request->url);
            }
            continue;
        }

        /* Ready to read a new request from FIFO */
        if (use_pipe && FD_ISSET(fifo_in_fd, &fdsetrecv)) {
            mylog(LOG_DBG, "[%d][%s] - select for FIFO", __LINE__, __func__);

            if ((request = malloc(sizeof(struct request))) == NULL) {
                mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }

            len_left = sizeof(struct sctp_pipe_data);
            bufptr = (char *) &(request->pipe_data);
            while (len_left > 0) {
                len = read(fifo_in_fd, bufptr + sizeof(struct sctp_pipe_data) - len_left, len_left);
                mylog(LOG_DBG, "[%d][%s] - fifo read : %d byte", __LINE__, __func__, len);
                if (len == 0) {
                    mylog(LOG_ERR, "[%d][%s] - fifo read failed - pipe closed", __LINE__, __func__);
                    use_pipe = 0;
                    free(request);
                    goto cleanupconn;
                } else if (len == -1) {
                    mylog(LOG_ERR, "[%d][%s] - fifo read failed: %d - %s", __LINE__, __func__, errno, strerror(errno));
                    use_pipe = 0;
                    free(request);
                    goto cleanupconn;
                }

                len_left -= len;
            }

            //request->pipe_data.path[strcspn(request->pipe_data.path, "\n")] = 0;
            num_req++;
            request->id = request->pipe_data.id;
            request->url = request->pipe_data.path;

            if (request->pipe_data.cookie_len > 0) {
                if ((bufptr = malloc(sizeof(char) * request->pipe_data.cookie_len + 1)) == NULL) {
                    mylog(LOG_ERR, "[%d][%s] - malloc failed", __LINE__, __func__);
                    exit(EXIT_FAILURE);
                }
                memset(bufptr, 97, request->pipe_data.cookie_len);
                bufptr[request->pipe_data.cookie_len] = '\0';
                if (asprintf(&(request->cookie), "Cookie: %s\r\n", bufptr) == -1) {
                  mylog(LOG_ERR, "[%d][%s] - asprintf failed", __LINE__, __func__);
                  exit(EXIT_FAILURE);
                }
            } else {
                request->cookie = NULL;
            }

            //snprintf(request->url, BUFSIZ, "%s", request->pipe_data.path);
            TAILQ_INSERT_TAIL(&requests_open, request, entries);
            num_req_open++;

            mylog(LOG_INF, "[%d][%s] - queueing : %d - %s", __LINE__, __func__, request->pipe_data.id, request->url);
            continue;
        }

        /* Ready to recv from socket */
        if (FD_ISSET(sd, &fdsetrecv)) {
            mylog(LOG_DBG, "[%d][%s] - select for sd recv", __LINE__, __func__);
        }

        /* Ready to send from socket */
        if (FD_ISSET(sd, &fdsetsend)) {
            mylog(LOG_DBG, "[%d][%s] - select for sd send", __LINE__, __func__);
        }

        /*
         * If in pipelined HTTP mode, put socket into non-blocking
         * mode, since we're probably going to want to try to send
         * several HTTP requests.
         */
        if (pipelined) {
            sdflags = fcntl(sd, F_GETFL);
            if (fcntl(sd, F_SETFL, sdflags | O_NONBLOCK) == -1) {
                mylog(LOG_ERR, "[%d][%s] - fcntl failed", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }
        }

        /* Construct requests and/or send them without blocking */
        while ((num_req_open > 0) && ((reqbuf == NULL) || pipelined)) {

            /* If not in the middle of a request, make one */
            if (reqbuf == NULL) {
                if ((request = TAILQ_FIRST(&requests_open)) == NULL) {
                    mylog(LOG_ERR, "[%d][%s] - no open requests left... fix it!", __LINE__, __func__);
                    exit(EXIT_FAILURE);
                }

                if ((reqbuflen = asprintf(&reqbuf,
                    "GET %s%s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "%s\r\n"
                    "%s" //cookie
                    "\r\n",
                    (request->url[0] == 47) ? "" : "/",
                    request->url,
                    servername,
                    env_HTTP_USER_AGENT,
                    (num_req_open == 1 && !use_pipe && !use_stdin) ? "Connection: Close" : "Connection: Keep-Alive",
                    (request->cookie != NULL) ? request->cookie : ""
                )) == -1) {
                    mylog(LOG_ERR, "[%d][%s] - asprintf failed", __LINE__, __func__);
                    exit(EXIT_FAILURE);
                }

                reqbufpos = 0;
            }

            /* If in pipelined mode or some streams not busy : send request */
            if (pipelined && sctp_streams_busy == 0) {
                if (send_request(sd, reqbuf, &reqbuflen, &reqbufpos) == -1) {
                    mylog(LOG_ERR, "[%d][%s] - send_request() failed", __LINE__, __func__);
                    goto conndied; //handle more precisely...
                }

                if (reqbufpos < reqbuflen) {
                    mylog(LOG_INF, "[%d][%s] - reqbufpos (%d) < reqbuflen (%d) or all streams busy...", __LINE__, __func__, reqbufpos, reqbuflen);
                    break;
                } else {
                    free(reqbuf);
                    reqbuf = NULL;

                    /* move queue element from open to pending */
                    if ((request = TAILQ_FIRST(&requests_open)) == NULL) {
                        mylog(LOG_PRG, "[%d][%s] - this should not happen... dafuq!?", __LINE__, __func__);
                        exit(EXIT_FAILURE);
                    }
                    TAILQ_REMOVE(&requests_open, request, entries);
                    TAILQ_INSERT_TAIL(&requests_pending, request, entries);

                    num_req_open--;
                    num_req_pending++;

                    mylog(LOG_INF, "[%d][%s] - %s : open -> pending (pipelined)", __LINE__, __func__, request->url);
                }
            }
        }

        /* Put connection back into blocking mode */
        if (pipelined) {
            if (fcntl(sd, F_SETFL, sdflags) == -1) {
                mylog(LOG_ERR, "[%d][%s] - fcntl : non-blocking -> blocking failed (non-blocking part)", __LINE__, __func__);
            }
        }

        /* sending last request ... do we need to blocking-send a request? */
        //felix : num_req_pending == 0 ?
        if (num_req_pending == 0 && num_req_open > 0 && sctp_streams_busy == 0) {
            if (send_request(sd, reqbuf, &reqbuflen, &reqbufpos) == -1) {
                mylog(LOG_ERR, "[%d][%s] - send_request() failed", __LINE__, __func__);
                goto conndied; //handle more precisely...
            }

            if (reqbufpos < reqbuflen) {
                mylog(LOG_ERR, "[%d][%s] - reqbufpos < reqbuflen or all streams busy...", __LINE__, __func__);
                if (errno != EAGAIN && sctp_streams_busy == 0) {
                    goto conndied;
                }
            } else {
                free(reqbuf);
                reqbuf = NULL;

                /* move queue element from open to pending */
                if ((request = TAILQ_FIRST(&requests_open)) == NULL) {
                    mylog(LOG_PRG, "[%d][%s] - this should not happen... dafuq?!", __LINE__, __func__);
                    exit(EXIT_FAILURE);
                }
                TAILQ_REMOVE(&requests_open, request, entries);
                TAILQ_INSERT_TAIL(&requests_pending, request, entries);

                num_req_open--;
                num_req_pending++;
                mylog(LOG_INF, "[%d][%s] - %s : open -> pending (blocking)", __LINE__, __func__, request->url);
            }
        }

        /* Get response and delete entry from pending list */

        /* take head element from pending queue */
        if ((request = TAILQ_FIRST(&requests_pending)) != NULL) {
            /* handle_response succeeded - remove pending element from queue */
            mylog(LOG_INF, "handling response for %s", request->url);
            if (handle_response(&sd, &fd, resbuf, &resbuflen, &resbufpos, request, &keepalive, &pipelined) == 0) {
                TAILQ_REMOVE(&requests_pending, request, entries);

                if (use_stdin) {
                    free(request->url);
                }

                free(request);

                /* We've finished this file! */
                num_req_pending--;
                num_req_finished++;
                if (protocol == IPPROTO_SCTP) {
                    sctp_stream_status[sctp_last_stream] = STREAM_FREE;
                    /* at least one stream is free for a new request */
                    sctp_streams_busy = 0;
                }
            } else {
                mylog(LOG_PRG, "[%d][%s] - handle_response() failed - aborting", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }

        } else if (request == NULL) {
            mylog(LOG_PRG, "[%d][%s] - no pending request left... timeout?", __LINE__, __func__);
            exit(EXIT_FAILURE);
            //goto cleanupconn;
        }


        /*
         * If necessary, clean up this connection so that we
         * can start a new one.
         */
        if (pipelined == 0 && keepalive == 0) {
            goto cleanupconn;
        }
        continue;

conndied:
        /*
         * Something went wrong -- our connection died, the server
         * sent us garbage, etc.  If this happened on the first
         * request we sent over this connection, give up.  Otherwise,
         * close this connection, open a new one, and reissue the
         * request.
         */

        if (num_req_open == 1) {
            mylog(LOG_PRG, "[%d][%s] - connection failure", __LINE__, __func__);
            exit(EXIT_FAILURE);
        }

cleanupconn:
        /*
         * Clean up our connection and keep on going
         */

        mylog(LOG_INF, "[%d][%s] - cleanupconn", __LINE__, __func__);
        shutdown(sd, SHUT_RDWR);
        close(sd);
        sd = -1;
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
        if (reqbuf != NULL) {
            free(reqbuf);
            reqbuf = NULL;
        }

        /* requeue all pending requests */
        while (num_req_pending > 0) {
            /* pending requests have to be resent */
            if ((request = TAILQ_FIRST(&requests_pending)) == NULL) {
                mylog(LOG_PRG, "[%d][%s] - this should not happen ... fix", __LINE__, __func__);
                exit(EXIT_FAILURE);
            }
            TAILQ_REMOVE(&requests_pending, request, entries);
            TAILQ_INSERT_TAIL(&requests_open, request, entries);
            num_req_open++;
            num_req_pending--;

            mylog(LOG_INF, "[%d][%s] - %s : pending -> open", __LINE__, __func__, request->url);
        }

        res = res0;
        pipelined = 0;
        resbuflen = 0;
        resbufpos = 0;
        continue;
    }

    mylog(LOG_PRG, "###### STATS ######");
    mylog(LOG_PRG, "\trequests      : %d", num_req_finished);
    mylog(LOG_PRG, "\t- # 200       : %d", stat_status_200);
    mylog(LOG_PRG, "\t- # 404       : %d", stat_status_404);
    mylog(LOG_PRG, "\t- # other     : %d", stat_status_other);
    mylog(LOG_PRG, "\tbytes header  : %d", stat_bytes_header);
    mylog(LOG_PRG, "\tbytes payload : %d", stat_bytes_payload);
    free(resbuf);
    freeaddrinfo(res0);

    return 0;
}
