
#include "ecp.h"

EXP_FUNC int STDCALL server_socket_init(int port)
{
	struct sockaddr_in serv_addr;
	int server_fd;
	char yes = 1;

	/* Create socket for incoming connections */
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

go_again:
	/* Construct local address structure */
	memset(&serv_addr, 0, sizeof(serv_addr));      /* Zero out structure */
	serv_addr.sin_family = AF_INET;                /* Internet address family */
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
	serv_addr.sin_port = htons(port);              /* Local port */

	/* Bind to the local address */
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
//		(*port)++;
		goto go_again;
	}
	/* Mark the socket so it will listen for incoming connections */
	if (listen(server_fd, 3000) < 0)
	{
		return -1;
	}

	return server_fd;
}

/**
 * init a client socket.
 */
EXP_FUNC int STDCALL client_socket_init(unsigned char *dnsName, uint16_t port)
{
	struct sockaddr_in address;
	int client_fd;

	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr =  inet_addr(dnsName);
	
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(client_fd <= 0)
	{
		perror("socket");
		return -1;
	}
	if (connect(client_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		perror("connect");
		AX_LOG("error :%s\n", getSystemErrorMsg() );
		SOCKET_CLOSE(client_fd);
		client_fd = -1;
	}

	return client_fd;
}

char *getSystemErrorMsg(void )
{
	static char output[1024];
#ifdef	WIN32	
	char	tmp[512];
	int val;

	val= GetLastError();
	memset(tmp, 0, sizeof(tmp));
	memset(output, 0, sizeof(output));
	
//	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, val, LANG_USER_DEFAULT, tmp, sizeof(tmp) - 1, NULL);
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
				  FORMAT_MESSAGE_MAX_WIDTH_MASK,
				  NULL, val, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				  (LPTSTR) tmp, sizeof(tmp) - 1, NULL);
	SNPRINTF(output, sizeof(output), ("failed with error %d: %s\n"), val, tmp);
#else
	SNPRINTF(output, sizeof(output),  strerror( errno) );
#endif

	return output;
}

/* blocking can be only used for client socket??? */
EXP_FUNC int STDCALL ecpTlsSocketBlock(int socket)
{
	int ret = 0;
#ifdef WIN32
	u_long argp = 1;
	ret = ioctlsocket(socket, FIONBIO, &argp);
#else
	int flags = fcntl(socket, F_GETFL, NULL);
	ret = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
#endif
	if( ret)
	{
		AX_LOG("Socket block failed:%s\n", getSystemErrorMsg() );
	}
	
	return ret;
}

EXP_FUNC int STDCALL ecpTlsThread(THREAD_FUNC_T func, void *data )
{
#ifdef WIN32
	CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)func, NULL, 0, NULL);
#else
	pthread_t thread;

	pthread_create(&thread, NULL, (void *(*)(void *))func, NULL);
	pthread_detach(thread);
#endif

	return 0;
}

int	ecpFillData(uint8_t *buf, uint8_t *data, uint32_t len)
{
	int	i =0;
	if(len/256==0)
	{
		buf[i++]=len;
	}
	else
	{
		buf[i++]=len/256;
		buf[i++]=len%256;
	}

	memcpy(buf+i, data, len);
	
	return i+len;
}

