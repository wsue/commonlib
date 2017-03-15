#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <numa.h>

#define PRNMSG(fmt,arg...) printf( "[%s:%d] " fmt , __func__,__LINE__,##arg)

// add into static int toIndex(short* arr, short arrLen, short* outArr, short outArrLen) { to let libvirt support numa cpu bind

int unia_get_nextnumacpu(int cpuid)
{
    int node = -1;
    int cnt  = -1;
    int i    = 0;
    unsigned long bits[256];
    struct bitmask  mask;

    if( numa_available() < 0 ){
        PRNMSG("no numa\n");
        return -1;
    }

    node = numa_node_of_cpu(cpuid);
    if( node < 0 ){
        PRNMSG("get node fail\n");
        return -1;
    }

    mask.size  = sizeof(bits) * sizeof(unsigned long);
    mask.maskp = bits;

    cnt = numa_num_configured_cpus();//numa_num_possible_cpus();
    if( cnt < cpuid || (numa_node_to_cpus(node, &mask) < 0 )){
        PRNMSG("get cpus %d on %d fail, %d/%s\n",cpuid,node,errno,strerror(errno));
        return -1;
    }

    for( i = cpuid +1; i != cpuid; i ++ ){
        if( i >= cnt ){
            i = 0;
        }
        if( numa_bitmask_isbitset(&mask,i) ){
            break;
        }
    }

    PRNMSG("cpu:%d on node:%d mask:(%d)%08x %08x %08x %08x next:%d\n",
            cpuid,node,cnt,bits[0],bits[1],bits[2],bits[3],i);

    return i == cpuid ? -1: i;
}


int main(int argc,char** argv)
{
    if( argc == 1 ){
        unia_get_nextnumacpu(0);
        unia_get_nextnumacpu(1);
    }
    else{
        unia_get_nextnumacpu(atoi(argv[1]));
    }
    return 0;
}

