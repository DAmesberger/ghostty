/* Generated configuration for libssh2 with OpenSSL backend */

/* Headers */
#define HAVE_UNISTD_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_UIO_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1

/* Functions */
#define HAVE_GETTIMEOFDAY 1
#define HAVE_STRTOLL 1
#define HAVE_SNPRINTF 1
/* Secure zero: explicit_bzero on Linux/glibc, memset_s on macOS */
#if defined(__APPLE__)
#define HAVE_MEMSET_S 1
#else
#define HAVE_EXPLICIT_BZERO 1
#endif
#define HAVE_POLL 1
#define HAVE_SELECT 1

/* Socket non-blocking support */
#define HAVE_O_NONBLOCK 1
#define HAVE_FIONBIO 1

/* Use OpenSSL as the crypto backend */
#define LIBSSH2_OPENSSL 1

/* Enable zlib compression (zlib@openssh.com) */
#define LIBSSH2_HAVE_ZLIB 1
