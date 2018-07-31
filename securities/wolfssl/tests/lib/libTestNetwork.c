
#include "libTest.h"


/* wolfSSL */
#ifndef TEST_IPV6
    const char* const wolfSSLIP   = "127.0.0.1";
#else
    const char* const wolfSSLIP   = "::1";
#endif
const word16      wolfSSLPort = 11111;

void build_addr(SOCKADDR_IN_T	*addr, const char* peer, word16 port, int udp)
{
	int useLookup = 0;
	(void)useLookup;
	(void)udp;

	memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
	/* peer could be in human readable form */
	if ( (peer != INADDR_ANY) && isalpha((int)peer[0]))
	{
#ifdef WOLFSSL_MDK_ARM
		int err;
		struct hostent* entry = gethostbyname(peer, &err);
#elif defined(WOLFSSL_TIRTOS)
		struct hostent* entry = DNSGetHostByName(peer);
#else
		struct hostent* entry = gethostbyname(peer);
#endif

		if (entry) {
			memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0], entry->h_length);
			useLookup = 1;
		}
		else
			err_sys("no entry for host");
	}
#endif


#ifndef TEST_IPV6
#if defined(WOLFSSL_MDK_ARM)
	addr->sin_family = PF_INET;
#else
	addr->sin_family = AF_INET_V;
#endif
	addr->sin_port = htons(port);
	if (peer == INADDR_ANY)
		addr->sin_addr.s_addr = INADDR_ANY;
	else {
		if (!useLookup)
			addr->sin_addr.s_addr = inet_addr(peer);
	}
	
#else
	addr->sin6_family = AF_INET_V;
	addr->sin6_port = htons(port);
	if (peer == INADDR_ANY)
		addr->sin6_addr = in6addr_any;
	else
	{
#ifdef HAVE_GETADDRINFO
		struct addrinfo  hints;
		struct addrinfo* answer = NULL;
		int    ret;
		char   strPort[80];

		memset(&hints, 0, sizeof(hints));

		hints.ai_family   = AF_INET_V;
		hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;

		SNPRINTF(strPort, sizeof(strPort), "%d", port);
		strPort[79] = '\0';

		ret = getaddrinfo(peer, strPort, &hints, &answer);
		if (ret < 0 || answer == NULL)
			err_sys("getaddrinfo failed");

		memcpy(addr, answer->ai_addr, answer->ai_addrlen);
		freeaddrinfo(answer);
#else
		printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
		addr->sin6_addr = in6addr_loopback;
#endif
	}
#endif
}


/* local socket */
void tcp_socket(SOCKET_T* sockfd, int udp)
{
	if (udp)
		*sockfd = socket(AF_INET_V, SOCK_DGRAM, 0);
	else
		*sockfd = socket(AF_INET_V, SOCK_STREAM, 0);

#ifdef USE_WINDOWS_API
	if (*sockfd == INVALID_SOCKET)
		err_sys("socket failed\n");
#elif defined(WOLFSSL_TIRTOS)
	if (*sockfd == -1)
		err_sys("socket failed\n");
#else
	if (*sockfd < 0)
		err_sys("socket failed\n");
#endif

#ifndef USE_WINDOWS_API 
#ifdef SO_NOSIGPIPE
	{
		int       on = 1;
		socklen_t len = sizeof(on);
		int       res = setsockopt(*sockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, len);
		if (res < 0)
			err_sys("setsockopt SO_NOSIGPIPE failed\n");
	}
#elif defined(WOLFSSL_MDK_ARM) || defined (WOLFSSL_TIRTOS)
	/* nothing to define */
#else  /* no S_NOSIGPIPE */
	signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */

#if defined(TCP_NODELAY)
	if (!udp)
	{
		int       on = 1;
		socklen_t len = sizeof(on);
		int       res = setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, &on, len);
		if (res < 0)
			err_sys("setsockopt TCP_NODELAY failed\n");
	}
#endif
#endif  /* USE_WINDOWS_API */
}

void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port, int udp)
{
	SOCKADDR_IN_T addr;
	
	build_addr(&addr, ip, port, udp);
	tcp_socket(sockfd, udp);

	printf("IP: %s;\tPort:%d; %s\n", ip, port, (udp==0)?"TCP":"UDP");

	if (!udp) {
		if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
			err_sys("tcp connect failed in test.h");
	}
}


void udp_connect(SOCKET_T* sockfd, void* addr, int addrSz)
{
	if (connect(*sockfd, (const struct sockaddr*)addr, addrSz) != 0)
		err_sys("udp connect failed");
}



int tcp_select(SOCKET_T socketfd, int to_sec)
{
#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_TIRTOS)
    fd_set recvfds, errfds;
    SOCKET_T nfds = socketfd + 1;
    struct timeval timeout = { (to_sec > 0) ? to_sec : 0, 0};
    int result;

    FD_ZERO(&recvfds);
    FD_SET(socketfd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(socketfd, &errfds);

    result = select(nfds, &recvfds, NULL, &errfds, &timeout);

    if (result == 0)
        return TEST_TIMEOUT;
    else if (result > 0) {
        if (FD_ISSET(socketfd, &recvfds))
            return TEST_RECV_READY;
        else if(FD_ISSET(socketfd, &errfds))
            return TEST_ERROR_READY;
    }

    return TEST_SELECT_FAIL;
#elif defined(WOLFSSL_TIRTOS)
    return TEST_RECV_READY;
#endif /* !WOLFSSL_MDK_ARM */
}


void tcp_listen(SOCKET_T* sockfd, word16* port, int useAnyAddr, int udp)
{
	SOCKADDR_IN_T addr;

	/* don't use INADDR_ANY by default, firewall may block, make user switch on */
	build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfSSLIP), *port, udp);
	tcp_socket(sockfd, udp);

#if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_ARM)
	{
		int       res, on  = 1;
		socklen_t len = sizeof(on);
		res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
		if (res < 0)
			err_sys("setsockopt SO_REUSEADDR failed\n");
	}
#endif

	if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
		err_sys("tcp bind failed");
	if (!udp) {
		if (listen(*sockfd, 5) != 0)
			err_sys("tcp listen failed");
	}
	
#if (defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API)) && !defined(WOLFSSL_TIRTOS)
	if (*port == 0) {
		socklen_t len = sizeof(addr);
		if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
#ifndef TEST_IPV6
			*port = ntohs(addr.sin_port);
#else
			*port = ntohs(addr.sin6_port);
#endif
		}
	}
#endif
}


int udp_read_connect(SOCKET_T sockfd)
{
    SOCKADDR_IN_T cliaddr;
    byte          b[1500];
    int           n;
    socklen_t     len = sizeof(cliaddr);

    n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK,  (struct sockaddr*)&cliaddr, &len);
    if (n > 0) {
        if (connect(sockfd, (const struct sockaddr*)&cliaddr, sizeof(cliaddr)) != 0)
            err_sys("udp connect failed");
    }
    else
        err_sys("recvfrom failed");

    return sockfd;
}

void udp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd, int useAnyAddr, word16 port, func_args* args)
{
    SOCKADDR_IN_T addr;

    (void)args;
    build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfSSLIP), port, 1);
    tcp_socket(sockfd, 1);


#if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_ARM)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys("setsockopt SO_REUSEADDR failed\n");
    }
#endif

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");

    #if (defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API)) && !defined(WOLFSSL_TIRTOS)
        if (port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    port = ntohs(addr.sin_port);
                #else
                    port = ntohs(addr.sin6_port);
                #endif
            }
        }
    #endif

#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && !defined(__MINGW32__)
    /* signal ready to accept data */
    {
    tcp_ready* ready = args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
    }
#elif defined (WOLFSSL_TIRTOS)
    /* Need mutex? */
    tcp_ready* ready = args->signal;
    ready->ready = 1;
    ready->port = port;
#endif

    *clientfd = udp_read_connect(*sockfd);
}


void tcp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              func_args* args, word16 port, int useAnyAddr,
                              int udp, int ready_file)
{
    SOCKADDR_IN_T client;
    socklen_t client_len = sizeof(client);

    if (udp) {
        udp_accept(sockfd, clientfd, useAnyAddr, port, args);
        return;
    }

    tcp_listen(sockfd, &port, useAnyAddr, udp);

#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && !defined(__MINGW32__)
    /* signal ready to tcp_accept */
    {
    tcp_ready* ready = args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
    }
#elif defined (WOLFSSL_TIRTOS)
    /* Need mutex? */
    tcp_ready* ready = args->signal;
    ready->ready = 1;
    ready->port = port;
#endif

    if (ready_file) {
#ifndef NO_FILESYSTEM
    #ifndef USE_WINDOWS_API
        FILE* srf = fopen("/tmp/wolfssl_server_ready", "w");
    #else
        FILE* srf = fopen("wolfssl_server_ready", "w");
    #endif

        if (srf) {
            fputs("ready", srf);
            fclose(srf);
        }
#endif
    }

    *clientfd = accept(*sockfd, (struct sockaddr*)&client,
                      (ACCEPT_THIRD_T)&client_len);
#ifdef USE_WINDOWS_API
    if (*clientfd == INVALID_SOCKET)
        err_sys("tcp accept failed");
#else
    if (*clientfd == -1)
        err_sys("tcp accept failed");
#endif
}


void tcp_set_nonblocking(SOCKET_T* sockfd)
{
    #ifdef USE_WINDOWS_API 
        unsigned long blocking = 1;
        int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
        if (ret == SOCKET_ERROR)
            err_sys("ioctlsocket failed");
    #elif defined(WOLFSSL_MDK_ARM) || defined (WOLFSSL_TIRTOS)
         /* non blocking not suppported, for now */ 
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        if (flags < 0)
            err_sys("fcntl get failed");
        flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
        if (flags < 0)
            err_sys("fcntl set failed");
    #endif
}


