cmake_minimum_required (VERSION 3.10)
project (cfpp)

FILE(GLOB sources *.c)
find_package(OpenSSL 1.1)

ADD_LIBRARY(cfpp ${sources})
target_include_directories(cfpp PRIVATE ${OPENSSL_INCLUDE_DIR})

