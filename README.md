# phttpget
A port of [phttpget.c](http://svnweb.freebsd.org/base/head/usr.sbin/portsnap/phttpget/phttpget.c)
adding SCTP support is provided in the file `phttpget.c`.
It runs on FreeBSD, Linux, MacOS X (using the SCTP NKE), and Solaris. It uses HTTP 1.1 and supports pipelining.

The transport protocol can be selected by setting the `HTTP_TRANSPORT_PROTOCOL` environment variable.
Supported values are `TCP` and `SCTP`. If the variable is not set, TCP is used.

The remote UDP encapsulation port can be configured by setting the `HTTP_SCTP_UDP_ENCAPS_PORT` environment
variable. Supported values are `0`, ..., `65535`. If it is unset or set to `0`, no UDP encapsulation
is used. Please note that for using UDP encapsulation, the local UDP encapsulation port must also be set
to a non-zero value. You can use `sudo sysctl -w net.inet.sctp.udp_tunneling_port=9899` on FreeBSD.
Please note that UDP encapsulation is only supported on FreeBSD and MacOS X (with the SCTP NKE).

The following example should work on FreeBSD using a tcsh:
```
env HTTP_TRANSPORT_PROTOCOL=SCTP HTTP_SCTP_UDP_ENCAPS_PORT=9899 phttpget bsd10.fh-muenster.de index.html
```
