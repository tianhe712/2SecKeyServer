#include "ServerOperation.h"

#include <iostream>
#include <pthread.h>

using namespace std;

typedef struct _pthread_info_t {
	//客户端对象指针
	TcpSocket *pSocket;
	//当前类指针
	ServerOperation *pServerOperation;
}pthread_info_t;

//线程处理函数 主要是与客户端进行数据交互
void *myroute(void *arg)
{
	int ret = -1;

	pthread_info_t *pInfo = NULL;

	pInfo = static_cast<pthread_info_t*>(arg); //1.free

	//1. 参数检查
	if (NULL == arg)
	{
		cout << "myroute 参数非法" << endl;
		return NULL;
	}

	//2. 接收客户端请求报文
	char *recvData = NULL;
	int recvLen = 0;

	pInfo->pSocket->recvMsg(&recvData, recvLen); //2.free

	//3. 创建密钥协商请求报文工厂类对象
	FactoryCodec *factoryCodec = new RequestFactory; //3.free

	//4. 创建请求报文解码对象
	Codec *codec = factoryCodec->createCodec(); //4.free

	//5. 解码请求报文  验证消息认证码
	RequestMsg *pRequestMsg = static_cast<RequestMsg *>(codec->msgDecode(recvData, recvLen)); //5.free

	//5.1 创建一个对象
	HMAC_CTX *hCtx = HMAC_CTX_new();
	if (NULL == hCtx)
	{
		cout << "HMAC_CTX_new failed.." << endl;
		return NULL;
	}

	//5.2 初始化
	char key[128];
	memset(key, 0, 128);
	sprintf(key, "@%s+%s@", pRequestMsg->clientId, pRequestMsg->serverId);
	ret = HMAC_Init_ex(hCtx, key, strlen(key), EVP_sha256(), NULL);
	if (1 != ret)
	{
		cout << "HMAC_Init_ex failed.." << endl;
		return NULL;
	}

	//5.3 添加数据
	ret = HMAC_Update(hCtx, (unsigned char *)pRequestMsg->r1, sizeof(pRequestMsg->r1));
	if (1 != ret)
	{
		cout << "HMAC_Update failed.." << endl;
		return NULL;
	}

	//5.4 计算结果
	unsigned char hmacMd[32];
	unsigned int hLen = 0;
	ret = HMAC_Final(hCtx, hmacMd, &hLen);
	if (1 != ret)
	{
		cout << "HMAC_Final failed.." << endl;
		return NULL;
	}

	//5.5 转化为字符串
	char buf[65];
	memset(buf, 0, 65);
	for (int i = 0; i < hLen; i++)
	{
		sprintf(&buf[i * 2], "%02X", hmacMd[i]);
	}

	//5.6 释放CTX
	HMAC_CTX_free(hCtx);

	cout << "HMAC: " << buf << endl;

	//5.7 比较消息认证码
	if (strcmp(pRequestMsg->authCode, buf) == 0)
	{
		cout << "消息认证码认证一致" << endl;
	}
	else
	{
		cout << "消息认证码认证不一致" << endl;
		return NULL;
	}

	//6. 根据请求报文cmdType类型 做出对应的响应
	char *sendData = NULL;
	int sendLen = 0;
	switch (pRequestMsg->cmdType)
	{
		//密钥协商
	case RequestCodec::NewOrUpdate:
		ret = pInfo->pServerOperation->secKeyAgree(pRequestMsg, &sendData, sendLen); //6.free
		break;
		//密钥校验
	case RequestCodec::Check:
		ret = pInfo->pServerOperation->secKeyCheck(pRequestMsg, &sendData, sendLen);
		break;
		//密钥注销
	case RequestCodec::Revoke:
		ret = pInfo->pServerOperation->secKeyRevoke(pRequestMsg, &sendData, sendLen);
		break;
	default:
		cout << "无效报文类型" << endl;
		ret = -1;
	}

	if (ret != 0)
	{
		cout << "秘钥协商服务端做业务失败..." << endl;
		return NULL;
	}

	//7. 发送响应报文
	pInfo->pSocket->sendMsg(sendData, sendLen);

	//8. 关闭连接
	pInfo->pSocket->disConnect();

	//9. 释放内存

	if (NULL != pInfo)
	{
		delete pInfo;
	}

	if (NULL != recvData)
	{
		delete[] recvData;
	}

	if (NULL != factoryCodec)
	{
		delete factoryCodec;
	}

	if (NULL != pRequestMsg)
	{
		codec->msgMemFree((void**)&pRequestMsg);
	}

	if (NULL != codec)
	{
		delete codec;
	}

	if (NULL != sendData)
	{
		delete[] sendData;
	}

	pthread_exit(NULL);
}

//构造函数
ServerOperation::ServerOperation(ServerInfo * info)
{
	//1. 参数检查
	if (NULL == info)
	{
		cout << "参数非法" << endl;
		return;
	}

	mInfo = new ServerInfo;
	if (NULL == mInfo)
	{
		cout << "new ServerInfo failed.." << endl;
		return;
	}
	memset(mInfo, 0, sizeof(ServerInfo));
	//拷贝数据
	memcpy(mInfo, info, sizeof(ServerInfo));

	mShm = new SecKeyShm(mInfo->shmKey, mInfo->maxNode);

	mServer = new TcpServer();

}

//析构函数
ServerOperation::~ServerOperation()
{
	delete mInfo;
	delete mShm;
	delete mServer;

	mInfo = NULL;
	mShm = NULL;
	mServer = NULL;
}

//启动密钥协商服务端  循环接受客户端连接 创建线程
void ServerOperation::startWork()
{
	pthread_info_t *pInfo = NULL;
	pthread_t tid = -1;

	//设置监听
	mServer->setListen(mInfo->sPort);

	cout << "密钥协商服务端处于监听状态" << endl;

	//循环接受客户端连接
	while (1)
	{
		//设置超时时间为1000秒
		mClient = mServer->acceptConn(1000);
		if (NULL == mClient && errno == ETIMEDOUT)
		{
			continue;
		}
		else if (NULL == mClient && errno != ETIMEDOUT)
		{
			break;
		}
		else
		{

			//内存冗余法 解决多线程传递参数问题
			pInfo = new pthread_info_t;
			memset(pInfo, 0, sizeof(pthread_info_t));
			pInfo->pSocket = mClient;
			pInfo->pServerOperation = this;

			//创建线程
			pthread_create(&tid, NULL, myroute, pInfo);
			//设置线程分离
			pthread_detach(tid);
		}
	}

	//关闭服务端
	mServer->closefd();
}

//秘钥协商
int ServerOperation::secKeyAgree(RequestMsg * reqmsg, char ** outData, int & outLen)
{
	int ret = -1;

	RespondMsg respondMsg;

	//0. 参数检查
	if (NULL == reqmsg || NULL == outData)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	//1. 组织密钥协商响应报文
	memset(&respondMsg, 0, sizeof respondMsg);
	respondMsg.rv = 0;
	strcpy(respondMsg.clientId, reqmsg->clientId);
	strcpy(respondMsg.serverId, reqmsg->serverId);

	respondMsg.secKeyId = 1;

	getRandString(sizeof(respondMsg.r2), respondMsg.r2);

	//2. 创建密钥响应编解码类工厂对象
	FactoryCodec *factoryCodec = new RespondFactory; //1.free

	//3. 创建响应报文编码对象
	Codec *codec = factoryCodec->createCodec(&respondMsg); //2.free

	//4. 编码响应报文
	codec->msgEncode(outData, outLen); 

	//5. 生成密钥 Sha512
	//5.1 初始化
	SHA512_CTX sCtx;
	ret = SHA512_Init(&sCtx);
	if (1 != ret)
	{
		cout << "SHA512_Init failed.." << endl;
		return -1;
	}

	//5.2 添加数据
	ret = SHA512_Update(&sCtx, reqmsg->r1, strlen(reqmsg->r1));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	ret = SHA512_Update(&sCtx, respondMsg.r2, strlen(respondMsg.r2));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	//5.3 计算结果
	unsigned char shaMd[64];
	memset(shaMd, 0, 64);
	ret = SHA512_Final(shaMd, &sCtx);
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}

	NodeShmInfo nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(nodeShmInfo));
	//5.4 转化为字符串
	for (int i = 0; i < 64; i++)
	{
		sprintf(&nodeShmInfo.secKey[i * 2], "%02X", shaMd[i]);
	}

	cout << nodeShmInfo.secKey << endl;

	//6. 写共享内存
	nodeShmInfo.status = 1;
	nodeShmInfo.secKeyId = respondMsg.secKeyId;
	strcpy(nodeShmInfo.clientId, respondMsg.clientId);
	strcpy(nodeShmInfo.serverId, respondMsg.serverId);

	mShm->shmWrite(&nodeShmInfo);

	//7. 写数据库

	//8. 释放内存
	if (NULL != factoryCodec)
	{
		delete factoryCodec;
	}

	if (NULL != codec)
	{
		delete codec;
	}

	return 0;
}

//密钥校验
int ServerOperation::secKeyCheck(RequestMsg * reqmsg, char ** outData, int & outLen)
{
	int ret = -1;

	RespondMsg respondMsg;

	NodeShmInfo nodeShmInfo;


	//0. 参数检查
	if (NULL == reqmsg || NULL == outData)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	//1. 组织密钥校验响应报文
	memset(&respondMsg, 0, sizeof respondMsg);


	//从共享内存中读取密钥信息
	memset(&nodeShmInfo, 0, sizeof(NodeShmInfo));
	ret = mShm->shmRead(reqmsg->clientId, reqmsg->serverId, &nodeShmInfo);
	if (0 != ret)
	{
		cout << "shmRead failed.." << endl;
		return -1;
	}

	cout << "密钥校验密钥： " << nodeShmInfo.secKey << endl;

	//计算密钥校验码
	//5.1 初始化
	SHA256_CTX sCtx;
	ret = SHA256_Init(&sCtx);
	if (1 != ret)
	{
		cout << "SHA512_Init failed.." << endl;
		return -1;
	}

	//5.2 添加数据
	ret = SHA256_Update(&sCtx, nodeShmInfo.secKey, sizeof(nodeShmInfo.secKey));
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}


	//5.3 计算结果
	unsigned char shaMd[32];
	memset(shaMd, 0, 32);
	ret = SHA256_Final(shaMd, &sCtx);
	if (1 != ret)
	{
		cout << "SHA512_Update failed.." << endl;
		return -1;
	}


	//5.4 转化为字符串
	for (int i = 0; i < 32; i++)
	{
		sprintf(&respondMsg.r2[i * 2], "%02X", shaMd[i]);
	}

	cout << "密钥校验码：" << respondMsg.r2 << endl;

	if (strcmp(reqmsg->r1, respondMsg.r2) == 0)
	{
		//校验ok
		respondMsg.rv = 0;
	}
	else
	{
		//校验失败
		respondMsg.rv = 1;
	}

	strcpy(respondMsg.clientId, reqmsg->clientId);
	strcpy(respondMsg.serverId, reqmsg->serverId);

	respondMsg.secKeyId = 1;


	//2. 创建密钥响应编解码类工厂对象
	FactoryCodec *factoryCodec = new RespondFactory; //1.free

	//3. 创建响应报文编码对象
	Codec *codec = factoryCodec->createCodec(&respondMsg); //2.free

	//4. 编码响应报文
	codec->msgEncode(outData, outLen);

	

	//8. 释放内存
	if (NULL != factoryCodec)
	{
		delete factoryCodec;
	}

	if (NULL != codec)
	{
		delete codec;
	}


	return 0;
}

//密钥注销
int ServerOperation::secKeyRevoke(RequestMsg * reqmsg, char ** outData, int & outLen)
{
	int ret = -1;

	RespondMsg respondMsg;

	NodeShmInfo nodeShmInfo;

	//0. 参数检查
	if (NULL == reqmsg || NULL == outData)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	//1. 组织密钥注销响应报文
	memset(&respondMsg, 0, sizeof respondMsg);
	respondMsg.rv = 0;

	strcpy(respondMsg.clientId, reqmsg->clientId);
	strcpy(respondMsg.serverId, reqmsg->serverId);
	getRandString(sizeof(respondMsg.r2), respondMsg.r2);
	//允许密钥注销
	respondMsg.secKeyId = 1;

	//从共享内存中注销密钥
	memset(&nodeShmInfo, 0, sizeof nodeShmInfo);
	ret = mShm->shmWrite(respondMsg.clientId, respondMsg.serverId, &nodeShmInfo);
	if (0 != ret)
	{
		cout << "shmWrite failed.." << endl;
		return -1;
	}

	//从数据库中将对应的网点密钥删除
	cout << "密钥协商服务端注销密钥成功" << endl;

	//2. 创建密钥响应编解码类工厂对象
	FactoryCodec *factoryCodec = new RespondFactory; //1.free

	//3. 创建响应报文编码对象
	Codec *codec = factoryCodec->createCodec(&respondMsg); //2.free

	//4. 编码响应报文
	codec->msgEncode(outData, outLen);



	//8. 释放内存
	if (NULL != factoryCodec)
	{
		delete factoryCodec;
	}

	if (NULL != codec)
	{
		delete codec;
	}


	return 0;
}

//服务端密钥查看  不用实现
int ServerOperation::secKeyView(void)
{
	return 0;
}

//生成随机序列函数
void ServerOperation::getRandString(int len, char * randBuf)
{
	int tag = -1;

	//参数检查
	if (len <= 0 || NULL == randBuf)
	{
		cout << "参数非法" << endl;
		return;
	}

	//设置随机种子
	srandom(time(NULL));

	memset(randBuf, 0, len);
	for (int i = 0; i < len; i++)
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
