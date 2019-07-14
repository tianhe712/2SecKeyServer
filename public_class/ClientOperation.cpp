#include "ClientOperation.h"
#include "RequestCodec.h"
#include "RespondCodec.h"
#include "RequestFactory.h"
#include "RespondFactory.h"
#include "SecKeyShm.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <iostream>

using namespace std;

//构造函数
ClientOperation::ClientOperation(ClientInfo * info)
{
	//参数检查
	if (NULL == info)
	{
		cout << "参数非法" << endl;
		return;
	}

	//分配客户端配置信息内存
	mInfo = new ClientInfo;
	if (NULL == mInfo)
	{
		cout << "new mInfo failed.." << endl;
		return;
	}
	memset(mInfo, 0, sizeof(ClientInfo));
	//拷贝数据
	memcpy(mInfo, info, sizeof(ClientInfo));

	//分配套接字空间
	mSocket = new TcpSocket;
	if (NULL == mSocket)
	{
		cout << "new TcpSocket failed.." << endl;
		return;
	}

	//分配共享内存空间
	mShm = new SecKeyShm(mInfo->shmKey, mInfo->maxNode);
	if (NULL == mShm)
	{
		cout << "new SecKeyShm failed.." << endl;
		return;
	}
}

//析构函数
ClientOperation::~ClientOperation()
{
	delete mInfo;
	delete mSocket;
	delete mShm;

	mInfo = NULL;
	mSocket = NULL;
	mShm = NULL;
}

//密钥协商
int ClientOperation::secKeyAgree(void)
{
	int ret = -1;

	//1）组织密钥协商请求报文
	RequestMsg requestMsg;
	memset(&requestMsg, 0, sizeof(RequestMsg));
	//密钥协商类型
	requestMsg.cmdType = RequestCodec::NewOrUpdate;
	//客户端编号
	strcpy(requestMsg.clientId, mInfo->clientId);
	//服务端编号
	strcpy(requestMsg.serverId, mInfo->serverId);

	//生成随机序列
	getRandString(sizeof(requestMsg.r1), requestMsg.r1);

	//1.1 创建对象
	HMAC_CTX *hCtx = HMAC_CTX_new();
	if (NULL == hCtx)
	{
		cout << "new HMAC_CTX_new failed.." << endl;
		return -1;
	}

	//1.2 初始化
	char key[128];
	memset(key, 0, sizeof(key));
	sprintf(key, "@%s+%s@", requestMsg.clientId, requestMsg.serverId);
	ret = HMAC_Init_ex(hCtx, key, strlen(key), EVP_sha256(), NULL);
	if (1 != ret)
	{
		cout << "HMAC_Init_ex failed.." << endl;
		return -1;
	}

	//1.3 添加数据
	ret = HMAC_Update(hCtx, (unsigned char *)requestMsg.r1, strlen(requestMsg.r1));
	if (1 != ret)
	{
		cout << "HMAC_Update failed.." << endl;
		return -1;
	}

	//1.4 计算结果
	unsigned char hmacMd[32];
	unsigned int hLen = -1;
	memset(hmacMd, 0, 32);
	ret = HMAC_Final(hCtx, hmacMd, &hLen);
	if (1 != ret)
	{
		cout << "HMAC_Final failed.." << endl;
		return -1;
	}

	//1.5 转化为字符串
	for (int i = 0; i < hLen; i++)
	{
		sprintf(&requestMsg.authCode[i * 2], "%02X", hmacMd[i]);
	}
	cout << "Hmac: " << requestMsg.authCode << endl;

	//1.6. 释放消息认证码内存
	HMAC_CTX_free(hCtx);


	//2）创建请求报文工厂类对象
	FactoryCodec *factoryCodec = new RequestFactory;

	//3）创建请求报文编解码类对象
	Codec *codec = factoryCodec->createCodec((void*)&requestMsg);

	//4）编码请求报文
	char *sendData = NULL;
	int sendDataLen = 0;
	codec->msgEncode(&sendData, sendDataLen);

	//5）连接到服务端
	mSocket->connectToHost(mInfo->serverIp, mInfo->serverPort);

	//6）发送请求报文
	mSocket->sendMsg(sendData, sendDataLen);

	//7）接收密钥协商响应报文
	char *recvData = NULL;
	int recvDataLen = -1;
	mSocket->recvMsg(&recvData, recvDataLen);

	delete factoryCodec;
	delete codec;

	delete[] sendData;

	//8）创建响应报文工厂类对象
	factoryCodec = new RespondFactory;

	//9）创建响应报文编解码对象
	codec = factoryCodec->createCodec();

	//10）解码响应报文
	RespondMsg *pRespondMsg = static_cast<RespondMsg*>(codec->msgDecode(recvData, recvDataLen));

	//11）根据响应状态码判断
	if (0 != pRespondMsg->rv)
	{
		cout << "密钥协商服务端响应失败..." << endl;
		return -1;
	}

	//12）使用哈希算法模拟生成密钥
	//12.1 初始化
	SHA512_CTX shaCTX;
	ret = SHA512_Init(&shaCTX);
	if (1 != ret)
	{
		cout << "SHA512_Init failed.." << endl;
		return -1;
	}

	//12.2 添加数据r1
	ret = SHA512_Update(&shaCTX, requestMsg.r1, strlen(requestMsg.r1));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	//12.3 添加数据r2
	ret = SHA512_Update(&shaCTX, pRespondMsg->r2, strlen(pRespondMsg->r2));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	//12.4 计算结果
	unsigned char shaMd[64];
	memset(shaMd, 0, 64);
	ret = SHA512_Final(shaMd, &shaCTX);
	if (1 != ret)
	{
		cout << "SHA512_Final failed.." << endl;
		return -1;
	}

	//12.5 转化为字符串
	NodeShmInfo nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeShmInfo));
	for (int i = 0; i < 64; i++)
	{
		sprintf(&nodeShmInfo.secKey[i * 2], "%02X", shaMd[i]);
	}

    cout << nodeShmInfo.secKey << endl;

	//13）写共享内存
	nodeShmInfo.status = 1;
	nodeShmInfo.secKeyId = pRespondMsg->secKeyId;
	strcpy(nodeShmInfo.clientId, mInfo->clientId);
	strcpy(nodeShmInfo.serverId, mInfo->serverId);
	mShm->shmWrite(&nodeShmInfo);

	//14）释放内存

	codec->msgMemFree((void**)&pRespondMsg);
	delete factoryCodec;
	delete codec;

	return 0;
}

//密钥校验
int ClientOperation::secKeyCheck(void)
{

	int ret = -1;

    NodeShmInfo nodeShmInfo;

	//1）组织密钥校验请求报文
	RequestMsg requestMsg;
	memset(&requestMsg, 0, sizeof(RequestMsg));
	//密钥协商类型
	requestMsg.cmdType = RequestCodec::Check;
	//客户端编号
	strcpy(requestMsg.clientId, mInfo->clientId);
	//服务端编号
	strcpy(requestMsg.serverId, mInfo->serverId);


    //从共享内存中读取密钥信息
    memset(&nodeShmInfo, 0, sizeof(nodeShmInfo));

    ret = mShm->shmRead(mInfo->clientId, mInfo->serverId, &nodeShmInfo);
    if (-1 == ret)
    {
        cout << "shmRead failed.." << endl; 
        return -1;
    }

    cout << "密钥校验密钥： " << nodeShmInfo.secKey << endl;


	//用哈希算法计算校验值
	//1.1 初始化
	SHA256_CTX shaCTX;
	ret = SHA256_Init(&shaCTX);
	if (1 != ret)
	{
		cout << "SHA512_Init failed.." << endl;
		return -1;
	}

	//1.2 添加数据r1
	ret = SHA256_Update(&shaCTX, nodeShmInfo.secKey, sizeof(nodeShmInfo.secKey));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	//12.4 计算结果
	unsigned char shaMd[32];
	memset(shaMd, 0, 32);
	ret = SHA256_Final(shaMd, &shaCTX);
	if (1 != ret)
	{
		cout << "SHA512_Final failed.." << endl;
		return -1;
	}

	//1.5 转化为字符串
	for (int i = 0; i < 32; i++)
	{
		sprintf(&requestMsg.r1[i * 2], "%02X", shaMd[i]);
	}

    cout <<"密钥校验码：" <<  requestMsg.r1 << endl;

	//生成随机序列
	//getRandString(sizeof(requestMsg.r1), requestMsg.r1);


	//1.1 创建对象
	HMAC_CTX *hCtx = HMAC_CTX_new();
	if (NULL == hCtx)
	{
		cout << "new HMAC_CTX_new failed.." << endl;
		return -1;
	}

	//1.2 初始化
	char key[128];
	memset(key, 0, sizeof(key));
	sprintf(key, "@%s+%s@", requestMsg.clientId, requestMsg.serverId);
	ret = HMAC_Init_ex(hCtx, key, strlen(key), EVP_sha256(), NULL);
	if (1 != ret)
	{
		cout << "HMAC_Init_ex failed.." << endl;
		return -1;
	}

	//1.3 添加数据
	ret = HMAC_Update(hCtx, (unsigned char *)requestMsg.r1, sizeof(requestMsg.r1));
	if (1 != ret)
	{
		cout << "HMAC_Update failed.." << endl;
		return -1;
	}

	//1.4 计算结果
	unsigned char hmacMd[32];
	unsigned int hLen = -1;
	memset(hmacMd, 0, 32);
	ret = HMAC_Final(hCtx, hmacMd, &hLen);
	if (1 != ret)
	{
		cout << "HMAC_Final failed.." << endl;
		return -1;
	}

	//1.5 转化为字符串
	for (int i = 0; i < hLen; i++)
	{
		sprintf(&requestMsg.authCode[i * 2], "%02X", hmacMd[i]);
	}
	cout << "Hmac: " << requestMsg.authCode << endl;

	//1.6. 释放消息认证码内存
	HMAC_CTX_free(hCtx);


	//2）创建请求报文工厂类对象
	FactoryCodec *factoryCodec = new RequestFactory;

	//3）创建请求报文编解码类对象
	Codec *codec = factoryCodec->createCodec((void*)&requestMsg);

	//4）编码请求报文
	char *sendData = NULL;
	int sendDataLen = 0;
	codec->msgEncode(&sendData, sendDataLen);

	//5）连接到服务端
	mSocket->connectToHost(mInfo->serverIp, mInfo->serverPort);

	//6）发送请求报文
	mSocket->sendMsg(sendData, sendDataLen);

	//7）接收密钥协商响应报文
	char *recvData = NULL;
	int recvDataLen = -1;
	mSocket->recvMsg(&recvData, recvDataLen);

	delete factoryCodec;
	delete codec;

	delete[] sendData;

	//8）创建响应报文工厂类对象
	factoryCodec = new RespondFactory;

	//9）创建响应报文编解码对象
	codec = factoryCodec->createCodec();

	//10）解码响应报文
	RespondMsg *pRespondMsg = static_cast<RespondMsg*>(codec->msgDecode(recvData, recvDataLen));

	//11）根据响应状态码判断
	if (0 != pRespondMsg->rv)
	{
        cout << "密钥校验失败" << endl;
	}
    else
    {
        cout << "密钥校验成功 " << endl; 
    }

	//14）释放内存

	codec->msgMemFree((void**)&pRespondMsg);
	delete factoryCodec;
	delete codec;

	return 0;
}

//密钥注销
int ClientOperation::secKeyRevoke(void)
{

	int ret = -1;

    NodeShmInfo nodeShmInfo;

	//1）组织密钥注销请求报文
	RequestMsg requestMsg;
	memset(&requestMsg, 0, sizeof(RequestMsg));
	//密钥协商类型
	requestMsg.cmdType = RequestCodec::Revoke;
	//客户端编号
	strcpy(requestMsg.clientId, mInfo->clientId);
	//服务端编号
	strcpy(requestMsg.serverId, mInfo->serverId);

	//生成随机序列
	getRandString(sizeof(requestMsg.r1), requestMsg.r1);


	//1.1 创建对象
	HMAC_CTX *hCtx = HMAC_CTX_new();
	if (NULL == hCtx)
	{
		cout << "new HMAC_CTX_new failed.." << endl;
		return -1;
	}

	//1.2 初始化
	char key[128];
	memset(key, 0, sizeof(key));
	sprintf(key, "@%s+%s@", requestMsg.clientId, requestMsg.serverId);
	ret = HMAC_Init_ex(hCtx, key, strlen(key), EVP_sha256(), NULL);
	if (1 != ret)
	{
		cout << "HMAC_Init_ex failed.." << endl;
		return -1;
	}

	//1.3 添加数据
	ret = HMAC_Update(hCtx, (unsigned char *)requestMsg.r1, sizeof(requestMsg.r1));
	if (1 != ret)
	{
		cout << "HMAC_Update failed.." << endl;
		return -1;
	}

	//1.4 计算结果
	unsigned char hmacMd[32];
	unsigned int hLen = -1;
	memset(hmacMd, 0, 32);
	ret = HMAC_Final(hCtx, hmacMd, &hLen);
	if (1 != ret)
	{
		cout << "HMAC_Final failed.." << endl;
		return -1;
	}

	//1.5 转化为字符串
	for (int i = 0; i < hLen; i++)
	{
		sprintf(&requestMsg.authCode[i * 2], "%02X", hmacMd[i]);
	}
	cout << "Hmac: " << requestMsg.authCode << endl;

	//1.6. 释放消息认证码内存
	HMAC_CTX_free(hCtx);


	//2）创建请求报文工厂类对象
	FactoryCodec *factoryCodec = new RequestFactory;

	//3）创建请求报文编解码类对象
	Codec *codec = factoryCodec->createCodec((void*)&requestMsg);

	//4）编码请求报文
	char *sendData = NULL;
	int sendDataLen = 0;
	codec->msgEncode(&sendData, sendDataLen);

	//5）连接到服务端
	mSocket->connectToHost(mInfo->serverIp, mInfo->serverPort);

	//6）发送请求报文
	mSocket->sendMsg(sendData, sendDataLen);

	//7）接收密钥协商响应报文
	char *recvData = NULL;
	int recvDataLen = -1;
	mSocket->recvMsg(&recvData, recvDataLen);

	delete factoryCodec;
	delete codec;

	delete[] sendData;

	//8）创建响应报文工厂类对象
	factoryCodec = new RespondFactory;

	//9）创建响应报文编解码对象
	codec = factoryCodec->createCodec();

	//10）解码响应报文
	RespondMsg *pRespondMsg = static_cast<RespondMsg*>(codec->msgDecode(recvData, recvDataLen));

	//11）根据响应状态码判断
	if (0 != pRespondMsg->rv)
	{
        cout << "密钥注销失败" << endl;
        return -1;
	}
    else
    {
        cout << "密钥注销成功 " << endl; 
    }

#if 1
    //从共享内存中注销密钥
    memset(&nodeShmInfo, 0, sizeof nodeShmInfo);
    ret = mShm->shmWrite(requestMsg.clientId, requestMsg.serverId, &nodeShmInfo);
    if (-1 == ret)
    {
        cout << "shmWrite failed.." << endl; 
        return -1;
    }

#endif
	//14）释放内存

	codec->msgMemFree((void**)&pRespondMsg);
	delete factoryCodec;
	delete codec;


	return 0;
}

//密钥查看
int ClientOperation::secKeyView(void)
{
    int ret = -1;

    NodeShmInfo nodeShmInfo;

    memset(&nodeShmInfo, 0, sizeof nodeShmInfo);

    //从共享内存读取密钥信息
    ret = mShm->shmRead(mInfo->clientId, mInfo->serverId, &nodeShmInfo);
    if (-1 == ret)
    {
        cout << "shmRead failed..." << endl; 
        return -1;
    }

    cout << "status: " << nodeShmInfo.status << endl;
    cout << "secKeyId: " << nodeShmInfo.secKeyId << endl;
    cout << "clientId: " << nodeShmInfo.clientId << endl;
    cout << "serverId: " << nodeShmInfo.serverId << endl;
    cout << "secKey: " << nodeShmInfo.secKey<< endl;


	return 0;
}

//获取随机字符序列
void ClientOperation::getRandString(int len, char * randBuf)
{
	int tag;
	int i;

	//字符种类
	//1. 大写字母 A-Z
	//2. 小写字母 a-z
	//3. 数字 0-9
	//4. 特殊字符 ~!@#$%^&*()_+

	//设置随机种子
	srandom(time(NULL));

	//参数检查
	if (len <= 0 || NULL == randBuf)
	{
		cout << "getRandString 参数非法" << endl;
		return;
	}
	memset(randBuf, 0, len);
	for (i = 0; i < len; i++)
	{
		//随机字符种类
		tag = random() % 4;

		switch (tag)
		{
			//大写字母
		case 0:
			randBuf[i] = 'A' + random() % 26;
			break;

			//小写字母
		case 1:
			randBuf[i] = 'a' + random() % 26;
			break;

			//数字
		case 2:
			randBuf[i] = '0' + random() % 10;
			break;

			//特殊字符
		case 3:
			randBuf[i] = "~!@#$%^&*()_+"[random() % 13];
 			break;
		}
	}
}
