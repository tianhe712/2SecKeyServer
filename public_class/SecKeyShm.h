#pragma once
#include "ShareMemory.h"

//网点密钥信息类
class NodeShmInfo
{
public:
	int status;     //密钥状态
	int secKeyId;   //密钥编号
	char clientId[12];  //客户端ID
	char serverId[12];  //服务端ID
	char secKey[128];   //密钥信息
};

//共享内存业务流类
class SecKeyShm : public ShareMemory
{
public:
	//打开共享内存
	SecKeyShm(int key);
	//创建共享内存
	SecKeyShm(int key, int maxNode);
	//打开共享内存
	SecKeyShm(char* pathName);
	//创建共享内存
	SecKeyShm(char* pathName, int maxNode);
	//析构函数
	~SecKeyShm();

	//将网点密钥信息写入共享内存
	int shmWrite(NodeShmInfo* pNodeInfo);

	//将网点密钥信息写入共享内存
	int shmWrite(const char* clientId, const char* serverId, NodeShmInfo* pNodeInfo);

	//从共享内存中读取网点密钥信息
	int shmRead(const char* clientId, const char* serverId, NodeShmInfo* pNodeInfo);

private:
	int mMaxNode = 20;      //最大网点数
};

