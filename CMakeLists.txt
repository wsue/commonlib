cmake_minimum_required (VERSION 2.2)
project (quiccli)
set(CMAKE_C_FLAGS "-g")
set(CMAKE_LD_FLAGS "-lpthread")

include_directories(.)

set(LIBS pthread dl  ssl crypto  )

set(CMAKE_CXX_FLAGS "-g -D_REENTRANT -DSSLPROTOTEST -Wall -fpic -m64 -funroll-loops -mfpmath=sse -msse4 -march=native ")
# proxy.cpp ssltest.cpp 
add_executable(sslproxy netapi.c sslproxy.c)
add_executable(tinyhttpd netapi.c tinyhttpd.c)
target_link_libraries(sslproxy ${LIBS} )
target_link_libraries(tinyhttpd ${LIBS} )
