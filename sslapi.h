#ifndef SSL_API_H_
#define SSL_API_H_

#include <netinet/in.h>
#include <errno.h>

#define WRAP_SYSAPI(ret,func)           do{ \
    ret = func;                             \
}while( ret == -1 && ( errno == EINTR))
#define WRAP_CLOSE_FD(fd) do{ \
    if( (fd) != -1 ){ close(fd); (fd) = -1; } }while(0)

#define SSLAPI_TRACE_OUTPUT(fmt,arg...) printf(fmt,##arg)

#define SSLAPI_ERRORCODE_SUCC       0
#define SSLAPI_ERRORCODE_INIT       1

#define TCP_DEFAULTBACK_LOG         10
#define SSLAPI_CONNECT_TIMEOUT      7

struct SSL;
struct SSLSocket{
    int     sd;
    SSL*    ssl;
};
static inline void SSLAPI_InitSocket(struct SSLSocket* sslsock){
    sslsock->sd             = -1;
    sslsock->ssl            = NULL;
}

int SocketAPI_TCPGetLocalPort(int sd);
int SocketAPI_TCPCreate(const char *serv,uint16_t port,int isbind,int connecttimeout_ms);
int SocketAPI_TCPAccept(int ld,struct sockaddr_storage* dst);

int SSLAPI_InitSSLServer(const char*certpem,const char* keypem,int port, const char* localaddr);
int SSLAPI_Accept(struct SSLSocket* sslsock,struct sockaddr_storage* dst);

int SSLAPI_InitSSLClient();
int SSLAPI_Connect(struct SSLSocket* sslsock, const char* svraddr,int port);

int SSLAPI_Read(struct SSLSocket* sslsock,char* buf,int len);
int SSLAPI_Write(struct SSLSocket* sslsock,const char* data,int len,int writeall);
void SSLAPI_Close(struct SSLSocket* sslsock);
void SSLAPI_Release();

#endif

