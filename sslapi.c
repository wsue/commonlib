#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <pthread.h>
//#include <linux/tcp.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sslapi.h"

struct SSLAPICtl{
    int         isinit_;
    int         listensd_;
    SSL_CTX*    servctx_;
    SSL_CTX*    clientctx_;
};

static struct SSLAPICtl     sSSLCtrl    = {
    0,-1,NULL,NULL
};



static int CreateTCP(struct addrinfo *pinfo,
        const struct sockaddr *addr,socklen_t addrlen,
        int isbind,int connecttimeout_ms)
{
    int sockfd = -1;
    if( pinfo ){
        sockfd = socket(pinfo->ai_family, pinfo->ai_socktype,
                pinfo->ai_protocol);
        addr    = pinfo->ai_addr;
        addrlen = pinfo->ai_addrlen;
    }
    else{
        sockfd = socket(AF_INET, SOCK_STREAM,0);
    }

    if(sockfd < 0) {
        return -1;
    }

    int on	= 1;
    if( isbind ){
        if( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ){
            SSLAPI_TRACE_OUTPUT( "tcp reuse port fail\n");
        }
        if(bind(sockfd, addr, addrlen) == 0
                && listen(sockfd, TCP_DEFAULTBACK_LOG) == 0 ) {
            return sockfd;
        }

        close(sockfd);
        return -1;        
    }

    int sock_opt    = 1;
    if( connecttimeout_ms != -1){
        ioctl(sockfd, FIONBIO, &sock_opt);
    }

    int connret = connect(sockfd, addr, addrlen);

    if( connret == -1 ){
        if( connecttimeout_ms != -1
                && (errno == EWOULDBLOCK || errno == EINPROGRESS) ){
            struct pollfd pfd;
            pfd.fd      = sockfd;
            pfd.events  = POLLOUT;
            int error   = 0;
            socklen_t errorlen = sizeof(error);

            int ret = -1;
            WRAP_SYSAPI(ret , poll( &pfd, 1, connecttimeout_ms ));
            if(  ret == 1
                    && getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&error, &errorlen) == 0 
                    && error == 0 ){
                connret = 0;
            }
            else{
                SSLAPI_TRACE_OUTPUT( "conn poll error:%d/%d,%d\n",ret,error,errno);
            }
        }
        else {
            SSLAPI_TRACE_OUTPUT( "conn error:%d/%d\n",connret,errno);
        }
    }

    if( connret == 0) {
        if( connecttimeout_ms != -1){
            sock_opt    = 0;
            ioctl(sockfd, FIONBIO, &sock_opt);
        }

        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on)) ;
        return sockfd;
    }

    close(sockfd);
    return -1;
}


int SocketAPI_TCPAccept(int ld,struct sockaddr_storage* dst)
{
    if( ld == -1 )
        return -1;

    struct sockaddr_storage tmp;
    if( !dst ) dst = &tmp;

    int sd  = -1;
    while(1){
        socklen_t len = sizeof(tmp);
        sd = accept(ld,(struct sockaddr *)dst,&len);
        if( sd >= 0 )
            break;

        if( sd == -1 ){
            if( errno == EINTR )
                continue;
            else
                return -1;
        }
    }

    int flag = 1;
    int ret = setsockopt( sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
        SSLAPI_TRACE_OUTPUT("Couldn't setsockopt(TCP_NODELAY)\n");
    }
    return sd;
}



int SocketAPI_TCPGetLocalPort(int sd)
{
    struct sockaddr_in addr;
    socklen_t           len = sizeof(addr);

    memset(&addr,0,sizeof(addr));
    if( getsockname(sd, (struct sockaddr*) &addr, &len) != 0) {
        return -1;
    }

    return htons(addr.sin_port);    
}

int SocketAPI_TCPCreate(const char *serv,uint16_t port,int isbind,int connecttimeout_ms)
{
    int 	sockfd	= -1;
    char	portstr[32];
    struct addrinfo hints, *res, *ressave;

    if( serv && *serv && inet_addr(serv) == inet_addr("127.0.0.1")){
        struct sockaddr_in addr;
        memset(&addr,0,sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = inet_addr(serv);

        return CreateTCP(NULL,(const struct sockaddr *)&addr,sizeof(addr),isbind,connecttimeout_ms);
    }

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family 		= PF_UNSPEC;
    hints.ai_socktype		= SOCK_STREAM;
    if( isbind ){
        hints.ai_flags		= AI_PASSIVE;
    }
    else{
        if( !serv || !serv[0] ){
            SSLAPI_TRACE_OUTPUT( "SockAPI_Create	param error for %s:%d bind:%d\n",serv ? serv: "NULL",port,isbind);
            return -1;
        }
    }

    sprintf(portstr,"%d",port);

    int ret =  getaddrinfo(serv, portstr, &hints, &res);
    if( ret != 0) {
        SSLAPI_TRACE_OUTPUT( "SockAPI_Create getaddr fail for %s:%d bind:%d\n",serv ? serv: "NULL",port,isbind);
        return -1;
    }

    ressave = res;

    do {
        struct sockaddr_in* paddr = (struct sockaddr_in*)res->ai_addr;
        if( isbind ){
            if( paddr->sin_addr.s_addr == htonl(0x7f000001))
                continue;
        }
        else{
            if( paddr->sin_addr.s_addr == 0)
                continue;
        }

        sockfd = CreateTCP(res,NULL,0,isbind,connecttimeout_ms);
        if(sockfd >= 0) {
            break;
        }
    }while((res = res->ai_next) != NULL);

    freeaddrinfo(ressave);
    if( sockfd >= 0 )
        return sockfd;

    SSLAPI_TRACE_OUTPUT( "SockAPI_Create fatal create fail for %s:%d bind:%d\n",serv ? serv: "NULL",port,isbind);
    return -1;
}

static int sendall(struct ProxyItem *item,const char* buf,int size)
{
    int ret = 0;
    while( size > 0 ){
        ret = item->sendfunc(item,buf,size);
        if( ret <= 0 ){
            ret = -1;
            break;
        }

        buf += ret;
        size -= ret;
    }

    return ret;
}

int SockAPI_Proxy(struct ProxyItem item[2])
{
    int ret = -1;
    while(1){
        int i   = 0;
        ret = -1;
        struct pollfd pfds[2]	 = {
            {item[0].sd,POLLIN_FLAG,0},
            {item[1].sd,POLLIN_FLAG,0}
        };
        WRAP_SYSAPI( ret , poll(pfds,2,-1));

        if( ret < 1 ){
            SSLAPI_TRACE_OUTPUT("poll fail %d/%d\n",ret,errno);
            break;
        }

        for( i = 0; i < 2 && ret > 0 ; i ++ ){
            if( !pfds[i].revents )
                continue;

            ret --;
            if( !IS_POLLIN_OK(pfds[i].revents ) ){
                ret = -1;
                break;
            }
            else{
                struct ProxyItem* input = i ==0 ? &item[0] : &item[1];
                struct ProxyItem* output = i ==1 ? &item[0] : &item[1];
                char    buf[8192];
                int     size    = input->recvfunc(input,buf,sizeof(buf));

                if( size < 1 || sendall(output,buf,size) < 0 ){
                    ret = -1;
                    break;
                }
            }
        }

        if( ret < 0 ){
            break;
        }
    }

    return ret;
}

static void ssl_init()
{ 
    if( sSSLCtrl.isinit_ )
        return ;

    sSSLCtrl.isinit_   = 1;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
}

static void ssl_cleanup()
{
    if( sSSLCtrl.isinit_ > 0 ){
        ERR_free_strings();
        EVP_cleanup();
    }

    sSSLCtrl.isinit_   = 0;
}

static SSL_CTX *ssl_servctx_init(const char*certpem,const char* keypem)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    //SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, certpem, SSL_FILETYPE_PEM) < 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keypem, SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static SSL *ssl_servctx_accept(int sd,SSL_CTX *ctx)
{
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

static SSL_CTX *ssl_clientctx_init()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

#if 1
    /* ---------------------------------------------------------- *
     * initialize SSL library and register algorithms             *
     * ---------------------------------------------------------- */
    if(SSL_library_init() < 0){
        SSLAPI_TRACE_OUTPUT("Could not initialize the OpenSSL library !\n");
        return NULL;
    }
#endif

    /* ---------------------------------------------------------- *
     * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
     * ---------------------------------------------------------- */
    method = SSLv23_client_method();

    /* ---------------------------------------------------------- *
     * Try to create a new SSL context                            *
     * ---------------------------------------------------------- */
    if ( (ctx = SSL_CTX_new(method)) == NULL){
        SSLAPI_TRACE_OUTPUT( "Unable to create a new SSL context structure.\n");
        return NULL;
    }
    /* ---------------------------------------------------------- *
     * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
     * ---------------------------------------------------------- */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    return ctx;
}

static SSL *ssl_clientctx_connect(int sd,SSL_CTX *ctx)
{
    SSL *ssl;
    /* ---------------------------------------------------------- *
     * Create new SSL connection state object                     *
     * ---------------------------------------------------------- */
    ssl = SSL_new(ctx);

    /* ---------------------------------------------------------- *
     * Attach the SSL session to the socket descriptor            *
     * ---------------------------------------------------------- */
    SSL_set_fd(ssl, sd);

    /* ---------------------------------------------------------- *
     * Try to SSL-connect here, returns 1 for success             *
     * ---------------------------------------------------------- */
    if ( SSL_connect(ssl) != 1 ){
        SSLAPI_TRACE_OUTPUT("Error: Could not build a SSL session \n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
#if 0
    X509                *cert = NULL;
    X509_NAME       *certname = NULL;
    /* ---------------------------------------------------------- *
     * Get the remote certificate into the X509 structure         *
     * ---------------------------------------------------------- */
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
        BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
    else
        BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

    /* ---------------------------------------------------------- *
     * extract various certificate information                    *
     * -----------------------------------------------------------*/
    certname = X509_NAME_new();
    certname = X509_get_subject_name(cert);

    /* ---------------------------------------------------------- *
     * display the cert subject here                              *
     * -----------------------------------------------------------*/
    BIO_printf(outbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outbio, certname, 0, 0);
    BIO_printf(outbio, "\n");

    /* ---------------------------------------------------------- *
     * Free the structures we don't need anymore                  *
     * -----------------------------------------------------------*/
    SSL_free(ssl);
    close(server);
    X509_free(cert);
    SSL_CTX_free(ctx);
    BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
#endif
}

int SSLAPI_InitSSLServer(const char*certpem,const char* keypem,int port, const char* localaddr)
{
    ssl_init();

    WRAP_CLOSE_FD(sSSLCtrl.listensd_);
    if( sSSLCtrl.servctx_ ){
        SSL_CTX_free(sSSLCtrl.servctx_);
        sSSLCtrl.servctx_   = NULL;
    }

    sSSLCtrl.listensd_ = SocketAPI_TCPCreate(localaddr,port,1,-1);
    if( sSSLCtrl.listensd_ < 0 ){
        SSLAPI_TRACE_OUTPUT("bind to port:%d/%s fail\n",port,localaddr ? localaddr : "0.0.0.0");
        return -1;
    }

    sSSLCtrl.servctx_   = ssl_servctx_init(certpem,keypem);
    if( sSSLCtrl.servctx_ != NULL ){
        return 0;
    }

    WRAP_CLOSE_FD(sSSLCtrl.listensd_);
    SSLAPI_TRACE_OUTPUT("bind to port:%d/%s create ssl fail\n",port,localaddr ? localaddr : "0.0.0.0");
    return -1;
}

int SSLAPI_InitSSLClient()
{
    ssl_init();

    if( sSSLCtrl.clientctx_ ){
        SSL_CTX_free(sSSLCtrl.clientctx_);
        sSSLCtrl.clientctx_   = NULL;
    }

    sSSLCtrl.clientctx_   = ssl_clientctx_init();
    return sSSLCtrl.clientctx_ != NULL ? 0 : -1;
}

void SSLAPI_Close(struct SSLSocket* sslsock)
{
    if( sslsock ){
        WRAP_CLOSE_FD(sslsock->sd);
        if( sslsock->ssl ){
            SSL_free(sslsock->ssl);
            sslsock->ssl    = NULL;
        }
    }
}

void SSLAPI_Release()
{
    WRAP_CLOSE_FD(sSSLCtrl.listensd_);
    if( sSSLCtrl.servctx_ ){
        SSL_CTX_free(sSSLCtrl.servctx_);
        sSSLCtrl.servctx_   = NULL;
    }

    if( sSSLCtrl.clientctx_ ){
        SSL_CTX_free(sSSLCtrl.clientctx_);
        sSSLCtrl.clientctx_   = NULL;
    }
    ssl_cleanup();
}

int SSLAPI_Accept(struct SSLSocket* sslsock,struct sockaddr_storage* dst)
{
    SSLAPI_InitSocket(sslsock);

    int sd  = SocketAPI_TCPAccept(sSSLCtrl.listensd_,dst);
    if( sd < 0 ){
        SSLAPI_TRACE_OUTPUT("accept fail\n");
        return -2;
    }
    else{
        SSL* ssl = ssl_servctx_accept(sd,sSSLCtrl.servctx_);
        if( ssl ){
            sslsock->sd     = sd;
            sslsock->ssl    = ssl;
            return 0;
        }
        SSLAPI_TRACE_OUTPUT("accept create ssl fail\n");
    }

    WRAP_CLOSE_FD(sslsock->sd);
    return -1;
}

int SSLAPI_Connect(struct SSLSocket* sslsock, const char* svraddr,int port)
{
    SSLAPI_InitSocket(sslsock);

    int sd  = SocketAPI_TCPCreate(svraddr,port,0,SSLAPI_CONNECT_TIMEOUT);
    if( sd < 0 ){
        SSLAPI_TRACE_OUTPUT("connect to %s:%d fail\n",svraddr ? svraddr : "NULL",port);
        return -1;
    }
    else{
        SSL* ssl = ssl_clientctx_connect(sd,sSSLCtrl.clientctx_);
        if( ssl ){
            sslsock->sd     = sd;
            sslsock->ssl    = ssl;
            return 0;
        }
        SSLAPI_TRACE_OUTPUT("connect to %s:%d fail\n",svraddr ? svraddr : "NULL",port);
    }

    WRAP_CLOSE_FD(sslsock->sd);
    return -1;
}

int SSLAPI_Read(struct SSLSocket* sslsock,char* buf,size_t len)
{
    if( !sslsock || !sslsock->ssl )
        return -1;

    int ret = SSL_read(sslsock->ssl,buf,len);
    if( ret > 0 ){
        return ret;
    }
    else{
        return -1;
    }
}


int SSLAPI_Write(struct SSLSocket* sslsock,const char* data,size_t len,int writeall)
{
    if( !sslsock || !sslsock->ssl )
        return -1;

    if( !writeall ){
        return SSL_write(sslsock->ssl,data,len);
    }
    else{
        uint16_t    size  = len;
        while( size > 0 ){
            int ret = SSL_write(sslsock->ssl,data,size);

            if( ret > 0 ){
                if( size >= ret ){
                    data += ret;
                    size  -= ret;
                    continue;
                }
            }

            SSLAPI_TRACE_OUTPUT("read data fail,will close ,ret:%d rest:%d total:%d\n",ret,size,len);
            ERR_print_errors_fp(stderr);
            return -1;
        }

        return len;
    }
}
    

#define CERT_PEM        "cert.pem"
#define KEY_PEM         "key.pem"
#define SERVER_ADDR     "10.64.66.229"
#define SERVER_PORT     443

static void test_client(const char* svraddr,int port)
{
    char    buf[4096]   = "";
    int     ret;

    struct SSLSocket   sslsock;
    SSLAPI_InitSocket(&sslsock);

    if( SSLAPI_InitSSLClient() ){
        SSLAPI_TRACE_OUTPUT("init client fail\n");
        return ;
    }

    if( SSLAPI_Connect(&sslsock, svraddr, port) != 0 ){
        SSLAPI_TRACE_OUTPUT("connect client fail\n");
        return ;
    }

    printf("connect to %s:%d succ\n",svraddr,port);
    ret = SSLAPI_Read(&sslsock,buf,sizeof(buf));
    printf("recv %d:%s\n",ret,buf);

    SSLAPI_Close(&sslsock);
}

int sslitem_recv(struct ProxyItem* item,char* buf, size_t size)
{
    struct SSLSocket*   sslsock = (struct SSLSocket *)item->priv;
    return SSLAPI_Read(sslsock,buf,size);
}

int sslitem_send(struct ProxyItem* item,const char* buf, size_t size)
{
    struct SSLSocket*   sslsock = (struct SSLSocket *)item->priv;
    return SSLAPI_Write(sslsock,buf,size,1);
}

static void* accept_connect(void *p)
{
    struct SSLSocket* svrsock   = (struct SSLSocket *)p;
    struct SSLSocket   clientsock;
    struct ProxyItem proxyitems[2]   = {
        {svrsock->sd,sslitem_recv,sslitem_send,p},
        {-1,sslitem_recv,sslitem_send,&clientsock}
    };

    SSLAPI_InitSocket(&clientsock);
    if( SSLAPI_Connect(&clientsock, SERVER_ADDR, SERVER_PORT) != 0 ){
        SSLAPI_TRACE_OUTPUT("connect client fail\n");
    }
    else{
        proxyitems[1].sd = clientsock.sd;
        SSLAPI_TRACE_OUTPUT("begin proxy %d->%d\n",proxyitems[0].sd,proxyitems[1].sd);
        SockAPI_Proxy(proxyitems);
        SSLAPI_TRACE_OUTPUT("end proxy %d->%d\n",proxyitems[0].sd,proxyitems[1].sd);
    }

    SSLAPI_Close(&clientsock);
    SSLAPI_Close(svrsock);

    free(p);
    return NULL;
}

static int StartTask(pthread_t *thrid,void* (*start_routine)(void*),void *arg)
{
    pthread_t slave_tid;
    int ret = pthread_create(thrid ? thrid : &slave_tid, NULL, start_routine, arg);
    if( ret == 0 && !thrid )
        pthread_detach(slave_tid);
    return ret == 0;
}

static void start_accept(struct SSLSocket* svrsock)
{
    struct SSLSocket* sock  = (struct SSLSocket *)malloc(sizeof(struct SSLSocket));
    memcpy(sock,svrsock,sizeof(*sock));
    StartTask(NULL,accept_connect,sock);
}


static void test_server(int port, const char* localaddr)
{
    if( SSLAPI_InitSSLClient() ){
        SSLAPI_TRACE_OUTPUT("init client fail\n");
        return ;
    }

    if( SSLAPI_InitSSLServer(CERT_PEM,KEY_PEM,port,localaddr) ){
        SSLAPI_TRACE_OUTPUT("init server %d/%s %s:%s fail\n",port,localaddr,CERT_PEM,KEY_PEM);
        return ;
    }

    while(1){
        struct SSLSocket sslsock;
        SSLAPI_InitSocket(&sslsock);

        if( SSLAPI_Accept(&sslsock,NULL) != 0 ){
            SSLAPI_TRACE_OUTPUT("accept server %d/%s %s:%s fail\n",port,localaddr,CERT_PEM,KEY_PEM);
            break;
        }

        start_accept(&sslsock);
    }
}

int main()
{
    //test_client("10.64.66.229",443);
    test_server(443,NULL);
    SSLAPI_Release();
    return 0;
}
