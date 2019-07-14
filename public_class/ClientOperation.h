#pragma once
#include "TcpSocket.h"
#include "SecKeyShm.h"

//密钥协商客户端配置信息
class ClientInfo
{
public:
	char clientId[12];			// 客户端ID
	char serverId[12];			// 服务器ID
	char authCode[65];			// 消息认证码
	char serverIp[32];			// 服务器IP
	unsigned int serverPort;	// 服务器端口
	int maxNode;				// 共享内存节点个数  客户端默认1
	int shmKey;					// 共享内存的Key
};

//密钥协商客户端业务类
class ClientOperation
{
public:
	ClientOperation(ClientInfo *info);
	~ClientOperation();

	// 秘钥协商
	int secKeyAgree(void);
	// 秘钥校验
	int secKeyCheck(void);
	// 秘钥注销
	int secKeyRevoke(void);
	// 秘钥查看
	int secKeyView(void);

private:
	//获取随机字符序列
	void getRandString(int len, char* randBuf);

private:
	//客户端配置信息
	ClientInfo *mInfo;
	//客户端套接字
	TcpSocket *mSocket;
	//
	SecKeyShm* mShm;
};

