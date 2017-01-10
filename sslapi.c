#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
//#include <linux/tcp.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

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


static void get_connect_name(int sd,int isfrom,char *name)
{
    struct sockaddr_in addr;
    socklen_t           len = sizeof(addr);

    const char* colorcode = isfrom ? "\e[45m" : "\e[44m";
    memset(&addr,0,sizeof(addr));
    if( getpeername(sd, (struct sockaddr*) &addr, &len) == 0) {
        sprintf(name,"%s%d/%s:%d\e[0m",colorcode,sd,inet_ntoa(addr.sin_addr),htons(addr.sin_port));
    }
    else{
        name[0] = 0;
    }
}

int SockAPI_Proxy(struct ProxyItem item[2])
{
    int ret = -1;
    get_connect_name(item[0].sd,1,item[0].name);
    get_connect_name(item[1].sd,0,item[1].name);

    SSLAPI_TRACE_OUTPUT("task:%d proxy %s -> %s \n",
            syscall(__NR_gettid), item[0].name,
            item[1].name);

    int direction = -1;
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
                char    buf[8192*4];
                int     size    = input->recvfunc(input,buf,sizeof(buf)-1);

                if( size > 0 && input->echostat != PROXYITEM_ECHOSTAT_NONE ){
                    if( input->echostat == PROXYITEM_ECHOSTAT_DISABLE ){
                        input->echostat = PROXYITEM_ECHOSTAT_NONE;
                        output->echostat = PROXYITEM_ECHOSTAT_NONE;
                    }
                    else{
                        buf[size ] = 0;
                        if( i != direction ){
                            SSLAPI_TRACE_OUTPUT_NOTITLE("]\n");
                            SSLAPI_TRACE_OUTPUT("%s <<<%d:[%s",input->name,size,buf);
                            direction   = i;
                        }
                        else{
                            SSLAPI_TRACE_OUTPUT_NOTITLE("%s",buf);
                        }
                        if( input->echostat == PROXYITEM_ECHOSTAT_SHOWONE ){
                            input->echostat  = PROXYITEM_ECHOSTAT_NONE;
                            output->echostat = PROXYITEM_ECHOSTAT_SHOWONE;
                        }
                    }
                }

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
    SSLAPI_TRACE_OUTPUT("\e[43m\e[34m FINISH  :%d proxy\e[0m %s -> %s \n",
            syscall(__NR_gettid), item[0].name,
            item[1].name);

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

static int p12file2ctx(SSL_CTX *ctx,const char* p12file)
{
    int         cert_done   = 0;
    X509        *x509;
    EVP_PKEY    *pri        = NULL;
    X509        *cert       = NULL;
    STACK_OF (X509) * ca    = NULL;
    const char *key_passwd = NULL; 

    PKCS12 *p12;
    FILE* f = fopen(p12file, "rb");

    if(!f) {
        SSLAPI_TRACE_OUTPUT("could not open PKCS12 file '%s'\n", p12file);
        return -1;
    }

    p12 = d2i_PKCS12_fp(f, NULL);
    fclose(f);

    if(!p12) {
        SSLAPI_TRACE_OUTPUT( "error reading PKCS12 file '%s'\n", p12file);
        return -1;
    }

    PKCS12_PBE_add();

    if(!PKCS12_parse(p12, key_passwd, &pri, &x509,
                &ca)) {
        SSLAPI_TRACE_OUTPUT("could not parse PKCS12 file, check password,  error %s \n",
                ERR_error_string(ERR_get_error(), NULL) );
        PKCS12_free(p12);
        return -1;
    }

    PKCS12_free(p12);


    if(SSL_CTX_use_certificate(ctx, x509) != 1) {
        SSLAPI_TRACE_OUTPUT(
                "could not load PKCS12 client certificate, error %s",
                ERR_error_string(ERR_get_error(), NULL) );
        goto fail;
    }

    if(SSL_CTX_use_PrivateKey(ctx, pri) != 1) {
        SSLAPI_TRACE_OUTPUT( "unable to use private key from PKCS12 file '%s'",
                p12file);
        goto fail;
    }

    if(!SSL_CTX_check_private_key (ctx)) {
        SSLAPI_TRACE_OUTPUT( "private key from PKCS12 file '%s' "
                "does not match certificate in same file", p12file);
        goto fail;
    }
    /* Set Certificate Verification chain */
    if(ca) {
        while(sk_X509_num(ca)) {
            /*
             * Note that sk_X509_pop() is used below to make sure the cert is
             * removed from the stack properly before getting passed to
             * SSL_CTX_add_extra_chain_cert(). Previously we used
             * sk_X509_value() instead, but then we'd clean it in the subsequent
             * sk_X509_pop_free() call.
             */
            X509 *x = sk_X509_pop(ca);
            if(!SSL_CTX_add_extra_chain_cert(ctx, x)) {
                X509_free(x);
                SSLAPI_TRACE_OUTPUT( "cannot add certificate to certificate chain");
                goto fail;
            }
            /* SSL_CTX_add_client_CA() seems to work with either sk_* function,
             * presumably because it duplicates what we pass to it.
             */
            if(!SSL_CTX_add_client_CA(ctx, x)) {
                SSLAPI_TRACE_OUTPUT( "cannot add certificate to client CA list");
                goto fail;
            }
        }
    }

    cert_done = 1;
fail:
    EVP_PKEY_free(pri);
    X509_free(x509);
    sk_X509_pop_free(ca, X509_free);

    return cert_done ? 0 : -1;
}

static DH* get_dh512()
{
    static unsigned char dh512_p[]={
        0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
        0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
        0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
        0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
        0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
        0x47,0x74,0xE8,0x33,
    };
    static unsigned char dh512_g[]={0x02,};
    DH *dh=DH_new();
    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
    return dh;
}

static SSL_CTX *ssl_servctx_init_p12(const char*p12file)
{
    const char* ciphers = "MEDIUM:HIGH:!RC4:!DSS:!aNULL@STRENGTH";

    int stat = 0;
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(SSLv23_server_method());

    if (ctx == NULL) {
        SSLAPI_TRACE_OUTPUT( "call to SSL_CTX_new() returned NULL\n");
        return NULL;
    }

    // Tell SSL that we don't want to request client certificates for
    // verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if( p12file2ctx(ctx,p12file) != 0 ){
        SSLAPI_TRACE_OUTPUT( "call to SSL_CTX_new() returned NULL\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
#if 0
    // Load the ciphers that they've asked for.
    // It could be inferred from the documentation for ciphers(1) that you 
    // can call SSL_CTX_set_cipher_list multiple times to build up a list 
    // of ciphers.  But that isn't how it works; rather you build up a list 
    // of ciphers in a string, and then pass that in a single call:

    // First of all disable any ciphers we've got by default
    ciphers[0] = 0;
    strcat(ciphers,"-ALL");

    // If they want cipher suites that require certificates, add them in
    if (enableCertSuites) {
        strcat(ciphers,":ALL:-aNULL");
    }

    // If they want the null ones, add them in
    if (enableNullSuites) {
        strcat(ciphers,":NULL");
    }

    // If they want the anonymous ones, add them in
    if (enableAnonSuites) {
        strcat(ciphers,":aNULL");
    }
#endif

    SSLAPI_DEBUG_OUTPUT("Calling SSL_CTX_set_cipher_list(\"%s\")...\n",ciphers);


    stat = SSL_CTX_set_cipher_list(ctx,ciphers);
    if (stat == 0) {
        SSLAPI_DEBUG_OUTPUT("SSL_CTX_set_cipher_list() failed");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Provide DH key information (if you don't do this, then ciphers that
    // require DH key exchange won't be used, even if they are in the list of
    // ciphers for the ctx)
    SSLAPI_DEBUG_OUTPUT("Calling SSL_CTX_set_tmp_dh()...\n");
    stat = SSL_CTX_set_tmp_dh(ctx,get_dh512());
    if (stat == 0) {
        SSLAPI_DEBUG_OUTPUT("SSL_CTX_set_cipher_list() failed");
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

    /* ---------------------------------------------------------- *
     * initialize SSL library and register algorithms             *
     * ---------------------------------------------------------- */
    if(SSL_library_init() < 0){
        SSLAPI_TRACE_OUTPUT("Could not initialize the OpenSSL library !\n");
        return NULL;
    }

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

//  @ init server, param:
//  certpem:    public key file, or p12 file(if keypem = NULL)
//  keypem:     private key file, or NULL(when certpem set to p12 file)
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

    if( keypem && keypem[0] ){
        sSSLCtrl.servctx_   = ssl_servctx_init(certpem,keypem);
        if( sSSLCtrl.servctx_ != NULL ){
            return 0;
        }
    }
    else{
        sSSLCtrl.servctx_   = ssl_servctx_init_p12(certpem);
        if( sSSLCtrl.servctx_ != NULL ){
            return 0;
        }
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
    






struct SSLProxyInfo{
    char    dstsvr[32];
    int     dstport;
};

static struct SSLProxyInfo  sSSLProxyInfo;



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







static int sslitem_recv(struct ProxyItem* item,char* buf, size_t size)
{
    struct SSLSocket*   sslsock = (struct SSLSocket *)item->priv;
    int ret = SSLAPI_Read(sslsock,buf,size);
    //printf(" read  %4d      = %d\n",item->sd,ret);
    return ret;
}

static int sslitem_send(struct ProxyItem* item,const char* buf, size_t size)
{
    struct SSLSocket*   sslsock = (struct SSLSocket *)item->priv;
    int ret= SSLAPI_Write(sslsock,buf,size,1);
    //printf(" write %d %4d  = %d\n",item->sd,size,ret);
    return ret;
}

static void* accept_connect(void *p)
{
    struct SSLSocket* svrsock   = (struct SSLSocket *)p;
    struct SSLSocket   clientsock;
    struct ProxyItem proxyitems[2]   = {
        {svrsock->sd,   sslitem_recv,sslitem_send,p, PROXYITEM_ECHOSTAT_SHOW},
        {-1,sslitem_recv,sslitem_send,&clientsock,PROXYITEM_ECHOSTAT_SHOW}
    };

    SSLAPI_InitSocket(&clientsock);
    if( SSLAPI_Connect(&clientsock, sSSLProxyInfo.dstsvr, sSSLProxyInfo.dstport) != 0 ){
        SSLAPI_TRACE_OUTPUT("connect client fail\n");
    }
    else{
        proxyitems[1].sd = clientsock.sd;
        SockAPI_Proxy(proxyitems);
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


int SSLAPI_Proxy(int localport, const char* localaddr,
        const char* dstsvr, int dstport,
        const char* certfile,const char* keyfile)
{
    if( !dstsvr || !dstsvr[0] || dstport < 1 || dstport > 65535 ){
        SSLAPI_TRACE_OUTPUT("wrong param\n");
        return -1;
    }

    memset(&sSSLProxyInfo,0,sizeof(sSSLProxyInfo));
    strncpy(sSSLProxyInfo.dstsvr,dstsvr,sizeof(sSSLProxyInfo.dstsvr)-1);
    sSSLProxyInfo.dstport   = dstport;

    if( SSLAPI_InitSSLClient() ){
        SSLAPI_TRACE_OUTPUT("init client fail\n");
        return -1;
    }

    if( SSLAPI_InitSSLServer(certfile,keyfile,localport,localaddr) ){
        SSLAPI_TRACE_OUTPUT("init server %d/%s %s:%s fail\n",localport,localaddr,certfile,keyfile);
        return -1;
    }

    while(1){
        struct SSLSocket sslsock;
        SSLAPI_InitSocket(&sslsock);

        if( SSLAPI_Accept(&sslsock,NULL) != 0 ){
            SSLAPI_TRACE_OUTPUT("accept server %d/%s %s:%s fail\n",localport,localaddr,certfile,keyfile);
            break;
        }
        else{
            struct SSLSocket* sock  = (struct SSLSocket *)malloc(sizeof(struct SSLSocket));
            memcpy(sock,&sslsock,sizeof(*sock));
            StartTask(NULL,accept_connect,sock);
        }
    }

    return 0;
}


int main(int argc, char** argv)
{
#if 0
    if( argc < 3 ){
        printf("%s [localaddr:]localport remoteaddr:remoteport p12certfile\n"
                " or \n%s [localaddr:]localport remoteaddr:remoteport cert.pem key.pem\n",
                argv[0],argv[0]);
        return 1;
    }
#endif

    //test_client("10.64.66.229",443);
    SSLAPI_Proxy(443,NULL,"10.64.66.229",443,  "default.p12",   NULL);
    //SSLAPI_Proxy(443,NULL,"10.64.66.229",443,  "cert.pem",   "key.pem");
    SSLAPI_Release();
    return 0;
}
