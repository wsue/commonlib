#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
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
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/dh.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "netapi.h"
#ifdef __cplusplus__
extern "C"{
#endif

#define SSLCTL_INITLOCK()    pthread_mutex_init(&sSSLCtrl.lock,NULL)
#define SSLCTL_LOCK()        pthread_mutex_lock(&sSSLCtrl.lock)
#define SSLCTL_UNLOCK()      pthread_mutex_unlock(&sSSLCtrl.lock)
#define SSLCTL_RELEASELOCK() pthread_mutex_destroy(&sSSLCtrl.lock)

struct SSLAPICtl{
    int         isinit_;
    int         listensd_;
    SSL_CTX*    servctx_;
    SSL_CTX*    clientctx_;
    pthread_mutex_t lock;
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
            if( setsockopt(sockfd, SOL_SOCKET, TCP_DEFER_ACCEPT , &on, sizeof(on)) != 0 ){
                SSLAPI_TRACE_OUTPUT( "tcp set accept defert fail\n");
            }
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


int SockAPI_TCPAccept(int ld,struct sockaddr_storage* dst)
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

    return sd;
}



int SockAPI_TCPGetLocalPort(int sd)
{
    struct sockaddr_in addr;
    socklen_t           len = sizeof(addr);

    memset(&addr,0,sizeof(addr));
    if( getsockname(sd, (struct sockaddr*) &addr, &len) != 0) {
	return -1;
    }

    return htons(addr.sin_port);    
}

int SockAPI_TCPCreate(const char *serv,uint16_t port,int isbind,int connecttimeout_ms)
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

int SockAPI_TCPGetInfo(int sd,struct tcp_info* tcpinfo)
{
    socklen_t len   = sizeof(*tcpinfo);
    int ret         = getsockopt(sd,SOL_TCP,TCP_INFO,tcpinfo,&len);
    return ret;
}

int SockAPI_TCPSetKeepAlive(int sd,int interval,int cnt)
{
    int keepAlive       = 1; // 开启keepalive属性
    int keepIdle        = interval; // 如该连接在5秒内没有任何数据往来,则进行探测 
    int keepInterval    = interval; // 探测时发包的时间间隔为5 秒
    int keepCount       = 3; // 探测尝试的次数.如果第1次探测包就收到响应了,则后2次的不再发.

    int ret1 = setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
    int ret2 = setsockopt(sd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
    int ret3 = setsockopt(sd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
    int ret4 = setsockopt(sd, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));
    return 0;
}


int SockAPI_Poll(int sd,int timeout_ms)
{
    int    haserror        = 0;
    return SockAPI_PollEx(sd,timeout_ms,&haserror);
}

int SockAPI_PollEx(int sd,int timeout_ms,int* haserror)
{
    int ret = -1;
    struct pollfd pfds	 = {sd,POLLIN_FLAG,0};
    WRAP_SYSAPI( ret , poll(&pfds,1,timeout_ms));
    if( ret == 1 && IS_POLLIN_OK(pfds.revents ) ){
        *haserror    = 0;
        return 0;
    }

    *haserror    = (ret != 0 );  // if not timeout, consider occur error
    return -1;
}

int SockAPI_Recv(int sd,char* p, size_t size,int timeout_ms)
{
    int ret;
    if( sd < 0 )
        return -1;

    if( timeout_ms != -1 ){
        if( SockAPI_Poll(sd,timeout_ms) != 0 )
            return -1;
    }

    WRAP_SYSAPI( ret , recv(sd,p,size,0) );

    if( ret < 0 ){
        SSLAPI_TRACE_OUTPUT( " %d recv data error, ret: %d,errno:%d\n" ,sd,ret , errno);

        return -1;
    }

    return ret;
}

int SockAPI_RecvN(int sd,char* p, size_t size,int timeout_ms,uint16_t interval_wait_ms){
    if( sd < 0 )
        return -1;

    while( size > 0 ){
        int ret;
        if( timeout_ms != -1 ){
            if( SockAPI_Poll(sd,timeout_ms) != 0 )
                return -1;

            timeout_ms = interval_wait_ms;
        }

        WRAP_SYSAPI( ret , recv(sd,p,size,0) );

        if( ret <= 0 ){
            SSLAPI_TRACE_OUTPUT( " %d recv data error, ret: %d,errno:%d\n" ,sd,ret , errno);

            return -1;
        }

        size	-= ret;
        p	+= ret;
    }

    return 0;
}

int SockAPI_SendN(int sd,const char* p, size_t size){
    if( sd < 0 )
        return -1;
    while( size > 0 ){
        int ret;
        WRAP_SYSAPI( ret , send(sd,p,size,0) );

        if( ret <= 0 ){
            SSLAPI_TRACE_OUTPUT( " %d send data error, ret: %d,errno:%d\n" ,sd,ret , errno);
            return -1;
        }

        size	-= ret;
        p	+= ret;
    }

    return 0;
}







static char* httpreq_geturi(char* httphead,struct HttpReqInfo* head)
{
    char*   pend    = NULL;
    char*   plast   = NULL;

    while( isspace(*httphead) )        httphead ++;
    pend            = strstr(httphead,"\r\n");

    if( !pend || pend == httphead ){
        return NULL;
    }

    plast           = pend -1;

    while( plast != httphead && isspace(*plast) ) plast --;

    /*  parse uri */
    *pend++         = 0;
    *pend++         = 0;

    head->cmd       = httphead;
    while( isalpha(*httphead) ){
        *httphead   = toupper(*httphead);
        httphead ++;
    }

    if( !isspace(*httphead) )
        return NULL;

    *httphead ++    = 0;
    while( isspace(*httphead) )        httphead ++;
    if( !*httphead )
        return NULL;

    head->uri       = httphead;

    while( (!isspace(*httphead)) && (*httphead != 0 ))        httphead ++;
    if( *httphead == 0 )
        return NULL;

    *httphead ++    = 0;
    while( isspace(*httphead) )        httphead ++;
    if( !*httphead )
        return NULL;

    if( strncasecmp(httphead,"HTTP/1.",7) == 0 
            && isdigit(httphead[7])
            && (httphead[8] == 0 )  )
        return pend;

    return NULL;
}


#define CONTENT_LENGTH_STR      "Content-length"
#define CONTENT_LENGTH_STR_LEN  14
/*  
 *
 *  param:
 *      httphead    [in]    http head, end with \r\n\0\0
 *      *cmd        [out]   http cmd
 *      *uri        [out]   http uri
 *      *head_info  [out]   point to head list
 *      *content_len [out]  content len info
 *  return  0:  succ
 *          -1: wrong http head
 */
static int httpheadreq2info(char* httphead,struct HttpReqInfo* head)
{
    char* pnext = NULL;
    memset(head,0,sizeof(*head));
    pnext       = httpreq_geturi(httphead,head);
    if( !pnext )
        return -1;

    head->head_begin    = pnext;
    while( pnext && (*pnext) ){
        char* pend      = strstr(pnext,"\r\n");
        char* ptoken    = strchr(pnext,':');
        if( !pend ){
            return -1;
        }

        if(ptoken > pend || !isalpha(*pnext)){
            pnext   = pend +2;
            continue;
        }

        if( ptoken - pnext >= CONTENT_LENGTH_STR_LEN ){
            if( strncasecmp(pnext,CONTENT_LENGTH_STR,CONTENT_LENGTH_STR_LEN) == 0 ){
                pnext   += CONTENT_LENGTH_STR_LEN;
                while( isspace(*pnext) ) pnext++;
                if( *pnext == ':' ){
                    head->content_len = strtoul(pnext+1,NULL,0);
                    break;
                }
            }
        }

        pnext   = pend +2;
    }

    return 0;
}

/*  read a http head(maybe include some http body)
 *      sd              [in]    
 *      p               [out]   keep recv http head(maybe include http body)
 *      size            [in]    p's size
 *      *head_size      [inout] input p's unparse data size
 *                              if succ, return http head size
 *      interval_wait_ms [in]   tcp recv wait interval
 *
 *  p  |                              size                                           |
 *     |--------head_size[in]------------|-------tcp recv -----|---------------------|
 *     |
 * return:  -1:                 fail
 *          size > 0            p's recv size
 */
static int http_recvreq(int sd,char* p, size_t size,size_t *head_size,uint16_t interval_wait_ms)
{
    char*   pstart      = p;
    char*   prcvbuf     = p + *head_size;
    char*   poldline    = NULL;
    char*   pend        = NULL;
    size_t  offset      = *head_size;

    *head_size          = 0;

    if( sd < 0 || size <= 7 || size < offset)
        return -1;

    if( offset > 0 ){
        prcvbuf[0]      = 0;
        pend    = strstr(pstart,"\r\n\r\n");
        if( pend ){
            if( pend != pstart ){
                pend        += 2;
                *pend++     = 0;
                *pend++     = 0;
                *head_size  = pend - pstart;
                return  size;
            }
            else{
                return -1;
            }
        }
    }

    while( offset < size ){
        int ret;
        if( SockAPI_Poll(sd,interval_wait_ms) != 0 )
            break;


        WRAP_SYSAPI( ret , recv(sd,prcvbuf,size - offset -1,0) );

        if( ret <= 0 ){
            SSLAPI_TRACE_OUTPUT( " %d recv data error, ret: %d,errno:%d\n" ,sd,ret , errno);
            break;
        }

        prcvbuf[ret]      = 0;

        if( offset > 3 ){
            pend    = strstr(prcvbuf-3,"\r\n\r\n");
        }
        else{
            pend    = strstr(prcvbuf,"\r\n\r\n");
        }

        offset	+= ret;
        prcvbuf	+= ret;

        if( pend ){
            if( pend != pstart ){
                pend        += 2;
                *pend++     = 0;
                *pend++     = 0;
            }
            else{
                pend    = NULL;
            }

            break;
        }

    }

    if( pend ){
        *head_size  = pend - pstart;
        return offset;
    }
    else{
        return -1;
    }
}

/*  read a http head(maybe include some http body)
 *      sd              [in]    
 *      head            [out]   http head info
 *      p               [out]   keep recv http head(maybe include http body)
 *      size            [in]    p's size
 *      *cache_size     [inout] input p's unparse data size
 *                              if succ, return next http head size
 *      interval_wait_ms [in]   tcp recv wait interval
 *
 *  p  |                              size                                                         |
 *     |--------cache_size[in]------------|-------tcp recv -------------------|--------------------|
 *     |-return value(one http req recv size) | cache_size(next http req size)|--------------------|
 * return:  -1:                 fail
 *          size > 0            one http request size(body may not full recv) 
 */
int SockAPI_RecvHttpReq(int sd,struct HttpReqInfo* head,char* p,size_t size,size_t* cache_size,uint16_t interval_wait_ms)
{
    int ret = -1;
    int recv_size;
    size_t rest_size;
    size_t httphdr_size;

    memset(head,0,sizeof(*head));
    recv_size  = http_recvreq(sd,p,size,cache_size,interval_wait_ms);
    if( (recv_size < 0) || (recv_size < *cache_size) )
        return -1;

    if( httpheadreq2info(p,head) != 0 )
        return -1;

    httphdr_size= *cache_size;
    rest_size   = recv_size - httphdr_size;
    if( head->content_len > 0 && rest_size > 0 ){
        head->content           = p + httphdr_size;
        head->content_readsz    = rest_size ;
    }
    if( rest_size <= head->content_len ){
        *cache_size = 0;
        return recv_size;
    }
    
    head->content_readsz    = head->content_len ;
    *cache_size             = rest_size - head->content_len;
    return httphdr_size + head->content_len;
}

static const char* respcode2str(int respcode)
{
    if( respcode >= 100 && respcode < 199 ){
        return "status info";
    }
    if( respcode >= 200 && respcode < 299 ){
        return "OK";
    }
    if( respcode >= 300 && respcode < 399 ){
        return "URI redirect";
    }
    if( respcode >= 400 && respcode < 499 ){
        return "client error";
    }

    return "Server Error";
    /*
       100～199——信息性状态码
       200～299——成功状态码
       300～399——重定向状态码     <p65>
       400～499——客户端错误状态码
       500～599——服务器错误状态码
       */
}

int SockAPI_SendHttpResp(int sd,int status, const char* statusstr,
        const char* content_type,const char* otherhead,
        const char* content, size_t content_len)
{
    char    buf[8192];
    size_t  offset  = 0;

    if( sd < 0 || ( content_len > 0 && !content ) || status < 100 || status >= 600 )
        return -1;


    if( !statusstr || !(*statusstr)) 
        statusstr   = respcode2str(status);
    offset = sprintf(buf,"HTTP/1.1 %d %s\r\n",status,statusstr);

    if( content_type && *content_type ){
        if( content_len < 1 )
            return -1;
        offset += sprintf(buf+offset,"Content-type: %s\r\nContent-length: %d\r\n",content_type,content_len);
    }

    if( otherhead && *otherhead ){
        int sz      = strlen(otherhead);
        if( sz <=2 
                || (otherhead[0] == '\r' && otherhead[1] == '\n' )
                || (otherhead[sz-2] != '\r' && otherhead[sz-1] != '\n' )
                || offset + sz +3> sizeof(buf) )
            return -1;

        memcpy(buf+offset,buf,sz);
        offset      += sz;
    }

    buf[offset++]   = '\r';
    buf[offset++]   = '\n';

    if( SockAPI_SendN(sd,buf,offset) == 0 
            && ( (content_len == 0 ) || SockAPI_SendN(sd,content,content_len) == 0 ) )
        return 0;

    return -1;
}

int SockAPI_SendHttpFileResp(int sd,const char* fname,const char* content_type, const char* other_head)
{
    char    buf[20480];

    int rc;                    /* holds return code of system calls */
    off_t offset = 0;          /* file offset */
    struct stat stat_buf;      /* argument to fstat */

    int fd;
    if( other_head && *other_head ){
        if( strlen(other_head) + 200 > sizeof(buf) )
            return -1;
    }

    fd  = openat(AT_FDCWD,fname,O_RDONLY);
    if( fd < 0 ){
        return SockAPI_SendHttpResp(sd,500,"open file fail",NULL,NULL,NULL,0);
    }

    /* get the size of the file to be sent */
    if( fstat(fd, &stat_buf) < 0 ){
        close(fd);
        return SockAPI_SendHttpResp(sd,500,"open file fail",NULL,NULL,NULL,0);
    }

    offset  = sprintf(buf,"HTTP/1.1 200 OK\r\nContent-type: %s\r\nContent-length: %d\r\n%s\r\n",
            content_type,stat_buf.st_size,other_head ? other_head : "");
    if( SockAPI_SendN(sd,buf,offset) != 0 ){
        close(fd);
        return -1;
    }

    /* copy file using sendfile */
    offset = 0;
    rc = sendfile (sd, fd, &offset, stat_buf.st_size);
    close(fd);
    if (rc == -1) {
        SSLAPI_TRACE_OUTPUT( "error from sendfile: %s\n", strerror(errno));
        return -1;
    }
    if (rc != stat_buf.st_size) {
        SSLAPI_TRACE_OUTPUT( "incomplete transfer from sendfile: %d of %d bytes\n",
                rc,
                (int)stat_buf.st_size);
        return -1;
    }

    return 0;
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





#if 0
static void SSL_pthreads_locking_callback(int mode, int type, char *file, int line);
static unsigned long SSL_pthreads_thread_id(void);

static pthread_mutex_t *lock_cs;
static long *lock_count;


static void SSL_thread_setup(void) {
    int i;

    lock_cs=(pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count=(long *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i=0; i<CRYPTO_num_locks(); i++) {
	lock_count[i]=0;
	pthread_mutex_init(&(lock_cs[i]),NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())SSL_pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())SSL_pthreads_locking_callback);
}

static void SSL_thread_cleanup(void) {
    int i;

    CRYPTO_set_locking_callback(NULL);
    fprintf(stderr,"cleanup\n");
    for (i=0; i<CRYPTO_num_locks(); i++) {
	pthread_mutex_destroy(&(lock_cs[i]));
	fprintf(stderr,"%8ld:%s\n",lock_count[i], CRYPTO_get_lock_name(i));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);

    fprintf(stderr,"done cleanup\n");
}

static void SSL_pthreads_locking_callback(int mode, int type, char *file, int line) {
#ifdef undef
    fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
	    CRYPTO_thread_id(),
	    (mode&CRYPTO_LOCK)?"l":"u",
	    (type&CRYPTO_READ)?"r":"w",file,line);
#endif
    /*
       if (CRYPTO_LOCK_SSL_CERT == type)
       fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
       CRYPTO_thread_id(),
       mode,file,line);
       */
    if (mode & CRYPTO_LOCK) {
	pthread_mutex_lock(&(lock_cs[type]));
	lock_count[type]++;
    } else {
	pthread_mutex_unlock(&(lock_cs[type]));
    }
}

static unsigned long SSL_pthreads_thread_id(void) {
    unsigned long ret;
    ret=(unsigned long)pthread_self();
    return(ret);
}
#else
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()
 
 
void handle_error(const char *file, int lineno, const char *msg)
{
  fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  /* exit(-1); */ 
}
 
/* This array will store all of the mutexes available to OpenSSL. */ 
static MUTEX_TYPE *mutex_buf= NULL;
 
static void locking_function(int mode, int n, const char *file, int line)
{
  if(mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}
 
static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}
 
int SSL_thread_setup(void)
{
  int i;
 
  mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
  if(!mutex_buf)
    return 0;
  for(i = 0;  i < CRYPTO_num_locks();  i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}
 
int SSL_thread_cleanup(void)
{
  int i;
 
  if(!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for(i = 0;  i < CRYPTO_num_locks();  i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}
#endif

static void ssl_init()
{ 
    if( sSSLCtrl.isinit_ )
	return ;

    sSSLCtrl.isinit_   = 1;
    SSLCTL_INITLOCK();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_thread_setup();
}

static void ssl_cleanup()
{
    if( sSSLCtrl.isinit_ > 0 ){
        ERR_free_strings();
        EVP_cleanup();
        SSL_thread_cleanup();
        SSLCTL_RELEASELOCK();
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

/*
 * The following function was generated using the openssl utility, using
 * the command : "openssl dhparam -dsaparam -C 512"
 */
DH *get_dh512()
{
#if 1
    return DH_get_1024_160();
#else
    static unsigned char dh512_p[]={
	0x9B,0x9A,0x2B,0x34,0xDA,0x9A,0x55,0x53,0x47,0xDB,0xCF,0xB4,
	0x26,0xAA,0x4D,0xFD,0x01,0x91,0x4A,0x19,0xE0,0x90,0xFA,0x6B,
	0x99,0xD6,0xE2,0x78,0xF3,0x31,0xD3,0x93,0x9B,0x7B,0xE1,0x65,
	0x57,0xFD,0x4D,0x2C,0x4E,0x17,0xE1,0xAC,0x30,0xB7,0xD0,0xA6,
	0x80,0x13,0xEE,0x37,0xD1,0x83,0xCD,0x5F,0x88,0x38,0x79,0x9C,
	0xFD,0xCE,0x85,0xED,
    };
    static unsigned char dh512_g[]={
	0x8B,0x17,0x22,0x46,0x30,0xAD,0xE5,0x06,0x42,0x60,0x15,0x79,
	0xA2,0x2F,0xD9,0xAA,0x7B,0xD7,0x8A,0x6F,0x39,0xEB,0x13,0x38,
	0x54,0xA6,0xBE,0xAD,0xC6,0x6A,0x17,0x95,0xBE,0x8B,0x29,0xE0,
	0x60,0x14,0x72,0xC9,0x5C,0x84,0x5D,0xD6,0x8B,0x57,0xD9,0x9D,
	0x08,0x60,0x73,0x78,0x3F,0xDD,0x26,0x2C,0x40,0x63,0xCF,0xE0,
	0xDC,0x58,0x7A,0x9C,
    };
    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    dh->length = 160;
    return(dh);
#endif
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

static int ssl_nonblock_accept(SSL* ssl,int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        SSLAPI_DEBUG_OUTPUT("fcntl: F_GETFL \n");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        SSLAPI_DEBUG_OUTPUT("fcntl: F_SETFL \n");
        return -1;
    }

    int status = -1;
    struct timeval tv, tvRestore;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    tvRestore = tv;

    fd_set writeFdSet;
    fd_set readFdSet;

    do{
        tv = tvRestore;
        FD_ZERO(&writeFdSet);
        FD_ZERO(&readFdSet);

        status = SSL_accept(ssl);
        switch (SSL_get_error(ssl, status))
        {
            case SSL_ERROR_NONE:
                status = 0; // To tell caller about success
                break; // Done

            case SSL_ERROR_WANT_WRITE:
                FD_SET(fd, &writeFdSet);
                status = 1; // Wait for more activity
                break;

            case SSL_ERROR_WANT_READ:
                FD_SET(fd, &readFdSet);
                status = 1; // Wait for more activity
                break;

            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
                // The peer has notified us that it is shutting down via
                // the SSL "close_notify" message so we need to
                // shutdown, too.
                printf("Peer closed connection during SSL handshake,status:%d", status);
                status = -1;
                break;
            default:
                printf("Unexpected error during SSL handshake,status:%d", status);
                status = -1;
                break;
        }

        if (status == 1)
        {
            // Must have at least one handle to wait for at this point.
            status = select(fd + 1, &readFdSet, &writeFdSet, NULL, &tv);

            // 0 is timeout, so we're done.
            // -1 is error, so we're done.
            // Could be both handles set (same handle in both masks) so
            // set to 1.
            if (status >= 1)
            {
                status = 1;
            }
            else // Timeout or failure
            {
                SSLAPI_DEBUG_OUTPUT("SSL handshake - peer timeout or failure");
                status = -1;
            }
        }

    }
    while (status == 1 && !SSL_is_init_finished(ssl));

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        SSLAPI_DEBUG_OUTPUT("fcntl: F_GETFL \n");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags & (~O_NONBLOCK)) < 0)
    {
        SSLAPI_DEBUG_OUTPUT("fcntl: F_SETFL \n");
        return -1;
    }


    return (status >= 0) ? 0 : -1;
}

static int ssl_block_accept(SSL* ssl,int sd)
{
    int rc = -1;
    int n = 0;
    while( ((rc=SSL_accept(ssl))!=1) && n <= 600){
    int ret =SSL_get_error(ssl,rc);
    if( ret ==SSL_ERROR_WANT_READ)
        usleep(100000);
        n++;
    }

    if( rc != 1 ){
        SSLAPI_DEBUG_OUTPUT("accept %p,%d,%d fail:%d/%d:%d\n",ssl,sd,n,rc,SSL_get_error(ssl,rc),errno);
    }

    return rc == 1 ? 0 :-1;
}

static SSL *ssl_servctx_accept(int sd,SSL_CTX *ctx)
{
    int flags;
    int status;
    struct timeval tv, tvRestore;
    SSL* ssl = SSL_new(ctx);
    SSLAPI_DEBUG_OUTPUT("accept %p,%d\n",ssl,sd);
    SSL_set_fd(ssl, sd);

    if( ssl_block_accept(ssl,sd) == 0 ){
        return ssl;
    }

    SSL_free(ssl);
    return NULL;
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

    sSSLCtrl.listensd_ = SockAPI_TCPCreate(localaddr,port,1,-1);
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

    int sd  = SockAPI_TCPAccept(sSSLCtrl.listensd_,dst);
    if( sd < 0 ){
        SSLAPI_TRACE_OUTPUT("accept fail\n");
        return -2;
    }
    else{
        SSLCTL_LOCK();
        SSL* ssl = ssl_servctx_accept(sd,sSSLCtrl.servctx_);
        SSLCTL_UNLOCK();
        if( ssl ){
            int flag = 1;
            int ret = setsockopt( sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
            if (ret == -1) {
                SSLAPI_TRACE_OUTPUT("Couldn't setsockopt(TCP_NODELAY)\n");
            }
            sslsock->sd     = sd;
            sslsock->ssl    = ssl;
            return 0;
        }
        SSLAPI_TRACE_OUTPUT("accept create ssl fail\n");
    }

    WRAP_CLOSE_FD(sd);
    return -1;
}

int SSLAPI_Connect(struct SSLSocket* sslsock, const char* svraddr,int port)
{
    SSLAPI_InitSocket(sslsock);

    int sd  = SockAPI_TCPCreate(svraddr,port,0,SSLAPI_CONNECT_TIMEOUT);
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
    




/*-----------------------------------------------------------------------------------------------------------------------------
 *
 *                  WRAP API
 *
 *----------------------------------------------------------------------------------------------------------------------------*/

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

int Task_Start(pthread_t *thrid,void* (*start_routine)(void*),void *arg)
{
    pthread_t slave_tid;
    int ret = pthread_create(thrid ? thrid : &slave_tid, NULL, start_routine, arg);
    if( ret == 0 && !thrid )
        pthread_detach(slave_tid);
    return ret == 0 ? 0 : -1;
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
            Task_Start(NULL,accept_connect,sock);
        }
    }

    return 0;
}









#define RECVHEAD_INTERVAL_MS            2000
static HTTPD_CALLBACK   shttpdcallback  = NULL;
static int              shttpdld        = -1;
static void* httpparse_task(void* p)
{
    char    buf[8192];
    size_t  cache_len   = 0;

    long val = (long)p;
    int sd  = (int) val;
    if( shttpdcallback(sd,HTTPD_STAT_INIT, NULL) != 0 ){
        close(sd);
        SSLAPI_DEBUG_OUTPUT("init parse %d error\n",sd);
        return NULL;
    }

    while( shttpdcallback ){
        struct HttpReqInfo  reqinfo;
        int callbackret;
        int ret = SockAPI_Poll(sd,-1);

        if( ret == -1 )
            break;

        ret = SockAPI_RecvHttpReq(sd,&reqinfo,buf,sizeof(buf),&cache_len,RECVHEAD_INTERVAL_MS);
        if( ret < 0 )
            break;

        SSLAPI_DEBUG_OUTPUT("recv %s %s %s %d:%s\n",
                reqinfo.cmd,reqinfo.uri,reqinfo.head_begin,reqinfo.content_len,reqinfo.content ? reqinfo.content : "");
        callbackret = shttpdcallback(sd,HTTPD_STAT_EXEC,&reqinfo);
        if( callbackret < 0 )
            break;
        if( callbackret > 0 ){
            if( SockAPI_SendHttpResp(sd,callbackret,NULL,NULL,NULL,NULL,0) != 0 )
                break;
        }
        memmove(buf,buf+ret,cache_len);

        if( cache_len > 0 ){
            memmove(buf,buf+ret,cache_len);
        }
    }

    shttpdcallback(sd,HTTPD_STAT_RELEASE, NULL);
    SSLAPI_DEBUG_OUTPUT("exit parse %d\n",sd);
    close(sd);
    return NULL;
}

static void* httpdtask(void * p )
{
    while( shttpdld >= 0 ){
        struct sockaddr_storage peeraddr;
        struct sockaddr_in      *pin = (struct sockaddr_in *)&peeraddr;

        int sd  = SockAPI_TCPAccept(shttpdld,&peeraddr);
        long val = sd;
        if( sd < 0 ){
            SSLAPI_DEBUG_OUTPUT("accept fail: %d, will stop\n",errno);
            break;
        }

        SSLAPI_DEBUG_OUTPUT("accept : %d from:%s:%d\n",
                sd,inet_ntoa(pin->sin_addr),
                htons(pin->sin_port));
        if( Task_Start(NULL,httpparse_task,(void *)val) == 0){
        }
        else{
            SSLAPI_DEBUG_OUTPUT("accept %d create task fail\n",sd);
            close(sd);
        }
    }

    close(shttpdld);
    shttpdld    = -1;
    return NULL;
}

int SockAPI_Httpd(const char* localaddr,uint16_t port,HTTPD_CALLBACK callback,int detached)
{
    if( shttpdld > 0 ){
        close(shttpdld);
        shttpdld    = -1;
    }

    if( !callback || port == 0 )
        return 0;

    shttpdld = SockAPI_TCPCreate(localaddr,port,1,-1);
    if( shttpdld < 0 ){
        SSLAPI_TRACE_OUTPUT("bind to %d fail\n",port);
        return -1;
    }

    shttpdcallback      = callback;
    SSLAPI_DEBUG_OUTPUT("bind to %d succ\n",port);
    long val    = shttpdld;
    if( detached ){
        Task_Start(NULL,httpdtask,NULL);
    }
    else{
        httpdtask(NULL);
    }
    return 0;
}


#ifdef __cplusplus__
};
#endif


