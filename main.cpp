#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstring>

#include "ServerOperation.h"

using namespace std;
//密钥协商服务端
int main() {
    ServerInfo info;

    //1. 从配置文件中读取服务端配置信息
    memset(&info, 0, sizeof(info));
    strcpy(info.serverId, "1111");
    strcpy(info.dbUser, "SECMNG");
    strcpy(info.dbPasswd, "SECMNG");
    strcpy(info.dbSid, "orcl");

    info.sPort = 10086;
    info.maxNode = 20;
    info.shmKey = 0x55;

    //2. 构造密钥协商服务端对象
    ServerOperation serverOperation(&info);

    //3. 启动密钥协商服务端
    serverOperation.startWork();

    //4. xxxx

    cout << "hello server" << endl;

    system("pause");
    std::cout << "Hello, 服务器开始World!" << std::endl;
    return 0;
}