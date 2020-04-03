CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(websockify C)
SET(CMAKE_C_FLAGS "-O3 -g -fPIE -fPIC -W -Wall -Wextra")

FIND_PACKAGE(OpenSSL REQUIRED)

ADD_EXECUTABLE(websockify
  src/websockify.c
  src/websocket.c
  src/websocket.h
  src/websocket_base64.c
  src/websocket_binary.c
  src/version.h
)
TARGET_LINK_LIBRARIES(websockify ${OPENSSL_LIBRARIES} resolv)
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/websockify DESTINATION sbin)
