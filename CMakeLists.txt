cmake_minimum_required(VERSION 3.12)
project(2SecKeyServer)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
include_directories(public_class)

#首先定义两个变量INC_DIR和LINK_DIR，用来表示头文件路径和库的路径：
set(INC_DIR /usr/local/include)
set(LINK_DIR /usr/local/lib64)
#然后依次设置头文件目录、库目录、要链接的库：
include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(libssl.so libcrypto.so)

add_executable(2SecKeyServer
        public_class/BaseASN1.cpp
        public_class/BaseASN1.h
        public_class/ClientOperation.cpp
        public_class/ClientOperation.h
        public_class/Codec.cpp
        public_class/Codec.h
        public_class/FactoryCodec.cpp
        public_class/FactoryCodec.h
        public_class/ItcastLog.cpp
        public_class/ItcastLog.h
        public_class/RequestCodec.cpp
        public_class/RequestCodec.h
        public_class/RequestFactory.cpp
        public_class/RequestFactory.h
        public_class/RespondCodec.cpp
        public_class/RespondCodec.h
        public_class/RespondFactory.cpp
        public_class/RespondFactory.h
        public_class/SecKeyShm.cpp
        public_class/SecKeyShm.h
        public_class/SequenceASN1.cpp
        public_class/SequenceASN1.h
        public_class/ShareMemory.cpp
        public_class/ShareMemory.h
        public_class/TcpServer.cpp
        public_class/TcpServer.h
        public_class/TcpSocket.cpp
        public_class/TcpSocket.h
        main.cpp
        ServerOperation.cpp
        ServerOperation.h)

#使用如下语句完成库的链接操作：
target_link_libraries(2SecKeyServer libssl.so libcrypto.so)


#使用多线程 报错 “对‘pthread_create’未定义的引用”解决：
find_package(Threads REQUIRED)
target_link_libraries(2SecKeyServer Threads::Threads)