#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "netapi.h"

#define LISTEN_PORT             8100
#define RECVHEAD_INTERVAL_MS    1000

#define URISTR_ACTCMD_DEL   "&act=del"


static int parse_indexreq(int sd)
{
    char    buf[81920];
    size_t  offset  = 0;
    struct dirent* dent;
    DIR * dir = opendir(".");
    if( !dir ){ 
        if( SockAPI_SendHttpResp(sd,500,"get dir list fail",NULL,NULL,NULL,0) != 0 )
            return -1;

        return 0;
    }

    offset  = sprintf(buf,"<html><head><title>iOS Log list</title></head><body>");

    while( dent = readdir(dir) ){
        int ret;
        if( dent->d_type & DT_DIR ){
            continue;
        }

        if( offset + strlen(dent->d_name) *2 + 100 > sizeof(buf) )
            break;

        offset  += sprintf(buf+offset,"<a href=\"%s\">%s</a><p>\n",dent->d_name,dent->d_name);
    }
    offset  += sprintf(buf+offset,"</body></html>");
    return  SockAPI_SendHttpResp(sd,200,"OK","text/html",NULL,buf,offset) == 0 ? 0 : -1;
}



static int parse_req(int sd,struct HttpReqInfo* reqinfo)
{
    char *splash = NULL;
    char *pact  = strstr(reqinfo->uri,URISTR_ACTCMD_DEL);
    if( pact ){
        *pact++ = 0;
    }

    splash  = strrchr(reqinfo->uri,'/');
    if( splash ){
        splash++;
        if( splash[0] == 0 )
            return parse_indexreq(sd);
    }
    else{
        splash  = reqinfo->uri;
    }

    return SockAPI_SendHttpFileResp(sd,splash,"text/plain", NULL);
}

static void* parse_task(void* p)
{
    char    buf[8192];
    size_t  cache_len   = 0;

    int sd  = (int) p;
    while(1){
        struct HttpReqInfo  reqinfo;
        int ret = SockAPI_Poll(sd,-1);
        if( ret == -1 )
            break;

        ret = SockAPI_RecvHttpReq(sd,&reqinfo,buf,sizeof(buf),&cache_len,RECVHEAD_INTERVAL_MS);
        if( ret < 0 )
            break;

        printf("recv %s %s %s %d:%s\n",
                reqinfo.cmd,reqinfo.uri,reqinfo.head_begin,reqinfo.content_len,reqinfo.content ? reqinfo.content : "");
        if( strcmp(reqinfo.cmd,"GET") || reqinfo.content_len > 0 ){
            if( SockAPI_SendHttpResp(sd,500,"Unsupport Command",NULL,NULL,NULL,0) != 0 )
                break;

            if( cache_len > 0 ){
                memmove(buf,buf+ret,cache_len);
            }
            continue;
        }

        if( parse_req(sd,&reqinfo) != 0 ){
            break;
        }


        memmove(buf,buf+ret,cache_len);
    }

    printf("exit parse %d\n",sd);
    close(sd);
    return NULL;
}


int main()
{
    int ld = SockAPI_TCPCreate(NULL,LISTEN_PORT,1,-1);
    if( ld < 0 ){
        printf("bind to %d fail\n",LISTEN_PORT);
        return 1;
    }

    printf("bind to %d succ\n",LISTEN_PORT);
    while( ld >= 0 ){
        struct sockaddr_storage peeraddr;
        struct sockaddr_in      *pin = (struct sockaddr_in *)&peeraddr;

        int sd  = SockAPI_TCPAccept(ld,&peeraddr);
        long val = sd;
        if( sd < 0 ){
            printf("accept fail: %d\n",errno);
            continue;
        }

        printf("accept : %d from:%s:%d\n",
                sd,inet_ntoa(pin->sin_addr),
                htons(pin->sin_port));
        if( Task_Start(NULL,parse_task,(void *)val) == 0){
        }
        else{
            printf("accept %d create task fail\n",sd);
            close(sd);
        }
    }

    close(ld);
    return 0;
}


