#ifndef SSL_API_H_
#define SSL_API_H_

#include <netinet/in.h>
#include <errno.h>


#define WRAP_SYSAPI(ret,func)           do{ \
    ret = func;                             \
}while( ret == -1 && ( errno == EINTR))
#define WRAP_CLOSE_FD(fd) do{ \
    if( (fd) != -1 ){ close(fd); (fd) = -1; } }while(0)

#define POLLIN_FLAG                (POLLIN|POLLHUP|POLLERR)
#define SET_POLLIN_FLAG(pollfds,fileid)    { (pollfds).fd	= fileid; (pollfds).events = POLLIN_FLAG; }
#define IS_POLLIN_OK(revent)  (((revent) & POLLIN) && (!((revent) & (POLLERR|POLLHUP|POLLNVAL))) )

#define SSLAPI_DEBUG_OUTPUT(fmt,arg...) printf( "[%s:%d] "fmt,__func__,__LINE__,##arg)
#define SSLAPI_TRACE_OUTPUT(fmt,arg...) printf( "[%s:%d] "fmt,__func__,__LINE__,##arg)
#define SSLAPI_TRACE_OUTPUT_NOTITLE(fmt,arg...) printf( fmt,##arg)

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

#define PROXYITEM_ECHOSTAT_NONE         0       // don't echo recv
#define PROXYITEM_ECHOSTAT_SHOW         1       // echo recv
#define PROXYITEM_ECHOSTAT_SHOWONE      2       // only show this, then disable
#define PROXYITEM_ECHOSTAT_DISABLE      3       // disable echo in all side
struct ProxyItem;
typedef int (*PROXYITEM_RECV)(struct ProxyItem* item,char* buf, size_t size);
typedef int (*PROXYITEM_SEND)(struct ProxyItem* item,const char* buf, size_t size);
struct ProxyItem{
    int             sd;
    PROXYITEM_RECV  recvfunc;
    PROXYITEM_SEND  sendfunc;
    void*           priv;
    int             echostat;
    char            name[32];
};

int SocketAPI_TCPGetLocalPort(int sd);
int SocketAPI_TCPCreate(const char *serv,uint16_t port,int isbind,int connecttimeout_ms);
int SocketAPI_TCPAccept(int ld,struct sockaddr_storage* dst);
int SockAPI_Proxy(struct ProxyItem *item);

int SSLAPI_InitSSLServer(const char*certpem,const char* keypem,int port, const char* localaddr);
int SSLAPI_Accept(struct SSLSocket* sslsock,struct sockaddr_storage* dst);

int SSLAPI_InitSSLClient();
int SSLAPI_Connect(struct SSLSocket* sslsock, const char* svraddr,int port);

int SSLAPI_Read(struct SSLSocket* sslsock,char* buf,size_t len);
int SSLAPI_Write(struct SSLSocket* sslsock,const char* data,size_t len,int writeall);
void SSLAPI_Close(struct SSLSocket* sslsock);
void SSLAPI_Release();

int SSLAPI_Proxy(int localport, const char* localaddr,
        const char* dstsvr, int dstport,
        const char* certfile,const char* keyfile);

#endif

