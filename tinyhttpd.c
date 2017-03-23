#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "netapi.h"

#define LISTEN_PORT             8100
#define RECVHEAD_INTERVAL_MS    1000

#define URISTR_ACTCMD_DEL   "&act=del"

static char   sRootDir[256];
static size_t sRootDir_sz;

static int parse_indexreq(int sd,const char* rootdir)
{
    char    buf[81920];
    size_t  offset  = 0;
    struct dirent* dent;
    DIR * dir = opendir(rootdir);
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



static int parse_req(int sd,int stat,struct HttpReqInfo* reqinfo)
{
    char *splash = NULL;
    char *pact  = NULL;
    char fullname[512];
    
    if( stat != HTTPD_STAT_EXEC )
        return 0;

    if( strcmp(reqinfo->cmd,"GET") || reqinfo->content_len > 0 )
        return 500;

    pact    = strstr(reqinfo->uri,URISTR_ACTCMD_DEL);
    if( pact ){
        *pact++ = 0;
    }

    splash  = strrchr(reqinfo->uri,'/');
    if( splash ){
        splash++;
        if( splash[0] == 0 )
            return parse_indexreq(sd,sRootDir);
    }
    else{
        splash  = reqinfo->uri;
    }

    if( strlen(splash) + sRootDir_sz +1> sizeof(fullname) )
        return 500;

    sprintf(fullname,"%s%s",sRootDir,splash);
    return SockAPI_SendHttpFileResp(sd,fullname,"text/plain", NULL);
}


static int runhttpd(int port,const char* root)
{
    char*   p;
    strcpy(sRootDir,root);
    sRootDir_sz = strlen(sRootDir);
    p   = sRootDir + sRootDir_sz;
    if( p[-1] != '/' ){
        *p++            = '/';
        *p++            = 0;
        sRootDir_sz     ++;
    }

    SockAPI_Httpd(NULL,LISTEN_PORT,parse_req,0);
    return 0;
}


int main()
{
    runhttpd(LISTEN_PORT,".");
    return 0;
}
