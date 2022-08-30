cmake_minimum_required (VERSION 3.10)
project (cfpp_test)

FILE(GLOB SOURCES *.c)
find_package(OpenSSL 1.1)


foreach(SOURCE_FILE ${SOURCES})
    get_filename_component(EXECUTABLE_NAME ${SOURCE_FILE} NAME_WE)
    add_executable(${EXECUTABLE_NAME} ${SOURCE_FILE})
    target_include_directories(${EXECUTABLE_NAME} PRIVATE "../src")
    target_include_directories(${EXECUTABLE_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${EXECUTABLE_NAME} PRIVATE "cfpp")
    target_link_libraries(${EXECUTABLE_NAME} PRIVATE ${OPENSSL_LIBRARIES})
endforeach(SOURCE_FILE ${SOURCES})
