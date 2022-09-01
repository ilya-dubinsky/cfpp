cmake_minimum_required (VERSION 3.10)
project (cfpp)

# Source files
FILE(GLOB SOURCES *.c)
FILE(GLOB HEADERS *.h)

# OpenSSL 1.1.1
find_package(OpenSSL 1.1.1)

# output a library
ADD_LIBRARY(cfpp ${SOURCES})
target_include_directories(cfpp PRIVATE ${OPENSSL_INCLUDE_DIR})

find_package(Doxygen) # Optional for generating doxygen files

if(Doxygen_FOUND)
	set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C "YES")
	set(DOXYGEN_EXTRACT_ALL "YES")
	doxygen_add_docs(docs ${HEADERS} ${SOURCES})
endif()
