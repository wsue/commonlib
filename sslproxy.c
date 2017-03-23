#include "netapi.h"

#if 1
// test
int main(int argc, char** argv)
{
#if 0
    if( argc < 3 ){
        printf("%s [localaddr:]localport remoteaddr:remoteport p12certfile\n"
                " or \n%s [localaddr:]localport remoteaddr:remoteport cert.pem key.pem\n",
                argv[0],argv[0]);
        return 1;
    }
    test_client("10.64.66.229",443);
#endif

    SSLAPI_Proxy(443,NULL,"10.64.66.229",443,  "TmmsDefaultTempCert.p12",   NULL);
    //SSLAPI_Proxy(443,NULL,"10.64.66.229",443,  "cert.pem",   "key.pem");
    SSLAPI_Release();
    return 0;
}
#endif

