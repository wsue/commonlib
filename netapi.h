#ifndef SSL_API_H_
#define SSL_API_H_

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <openssl/ssl.h>

#ifdef __cplusplus__
extern "C"{
#endif

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
#define SSLAPI_CONNECT_TIMEOUT_MS   200

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

struct HttpReqInfo{
    //  this point to origbuf
    char* cmd;                // in upper case
    char* uri;
    char* head_begin;         //  multi lines, each line end with \r\n
    char* content;
    size_t      content_len;        //  total body size
    size_t      content_readsz;     //  body has readed
};

int Task_Start(pthread_t *thrid,void* (*start_routine)(void*),void *arg);

int SockAPI_TCPGetLocalPort(int sd);
int SockAPI_TCPCreate(const char *serv,uint16_t port,int isbind,int connecttimeout_ms);
int SockAPI_TCPAccept(int ld,struct sockaddr_storage* dst);
int SockAPI_TCPGetInfo(int sd,struct tcp_info* tcpinfo);
int SockAPI_TCPSetKeepAlive(int sd,int interval_ms,int );

int SockAPI_Poll(int sd,int timeout_ms);
int SockAPI_PollEx(int sd,int timeout_ms,int* haserror);
int SockAPI_Recv(int sd,char* p, size_t size,int timeout_ms);
int SockAPI_RecvN(int sd,char* p, size_t size,int timeout_ms,uint16_t interval_wait_ms);
int SockAPI_SendN(int sd,const char* p, size_t size);


int SockAPI_RecvHttpReq(int sd,struct HttpReqInfo* head,char* p,size_t size,size_t* cache_size,uint16_t interval_wait_ms);
int SockAPI_SendHttpFileResp(int sd,const char* fname,const char* content_type, const char* other_head);
int SockAPI_SendHttpResp(int sd,int status, const char* statusstr,
        const char* content_type,const char* otherhead,
        const char* content, size_t content_len);

int SockAPI_Proxy(struct ProxyItem *item);

int SSLAPI_InitSSLServer(const char*certpem,const char* keypem,int port, const char* localaddr);
int SSLAPI_Accept(struct SSLSocket* sslsock,struct sockaddr_storage* dst);

int SSLAPI_InitSSLClient();
int SSLAPI_Connect(struct SSLSocket* sslsock, const char* svraddr,int port);

int SSLAPI_Read(struct SSLSocket* sslsock,char* buf,size_t len);
int SSLAPI_Write(struct SSLSocket* sslsock,const char* data,size_t len,int writeall);
void SSLAPI_Close(struct SSLSocket* sslsock);
void SSLAPI_Release();

/*  wrap api    */
int SSLAPI_Proxy(int localport, const char* localaddr,
        const char* dstsvr, int dstport,
        const char* certfile,const char* keyfile);

#define HTTPD_STAT_INIT         1
#define HTTPD_STAT_EXEC         2
#define HTTPD_STAT_RELEASE      3
/*  return  0:  succ,and has send http resp
 *          >0: http status code(when httpdstat == HTTPD_STAT_EXEC)
 *          -1: error, need terminate connection
 */
typedef int (*HTTPD_CALLBACK)(int sd,int httpdstat,struct HttpReqInfo *reqinfo);

//  tiny http server, multi thread + callback
//  if callback == NULL || port == 0 , then stop current tiny http server
int SockAPI_Httpd(const char* localaddr,uint16_t port,HTTPD_CALLBACK callback,int detached);
#ifdef __cplusplus__
};
#endif

#endif

