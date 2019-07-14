#include "RespondCodec.h"
#include <iostream>

using namespace std;

//构造函数 构造解码对象
RespondCodec::RespondCodec()
{
	//分配空间
	mRespondMsg = new RespondMsg;
	if (NULL == mRespondMsg)
	{
		cout << "new RespondMsg failed..." << endl;
		return;
	}

	//清零
	memset(mRespondMsg, 0, sizeof(RespondMsg));
}

//构造函数 构造编码对象
RespondCodec::RespondCodec(RespondMsg * msg)
{
	//分配空间
	mRespondMsg = new RespondMsg;
	if (NULL == mRespondMsg)
	{
		cout << "new RespondMsg failed..." << endl;
		return;
	}

	//清零
	memset(mRespondMsg, 0, sizeof(RespondMsg));

	//拷贝数据
	memcpy(mRespondMsg, msg, sizeof(RespondMsg));
}

//析构函数
RespondCodec::~RespondCodec()
{
	delete mRespondMsg;

	mRespondMsg = NULL;
}

//编码函数
int RespondCodec::msgEncode(char ** outData, int & len)
{
	int ret = -1;

	//1. 参数检查
	if (NULL == outData)
	{
		cout << "参数非法." << endl;
		return -1;
	}

	//2. 编码rv
	ret = writeHeadNode(mRespondMsg->rv);
	if (0 != ret)
	{
		cout << "writeHeadNode failed..." << endl;
		return -1;
	}

	//3. 编码clientId
	ret = writeNextNode(mRespondMsg->clientId, strlen(mRespondMsg->clientId));
	if (0 != ret)
	{
		cout << "writeNextNode failed..." << endl;
		return -1;
	}

	//4. 编码serverId
	ret = writeNextNode(mRespondMsg->serverId, strlen(mRespondMsg->serverId));
	if (0 != ret)
	{
		cout << "writeNextNode failed..." << endl;
		return -1;
	}

	//5. 编码r2
	ret = writeNextNode(mRespondMsg->r2, strlen(mRespondMsg->r2));
	if (0 != ret)
	{
		cout << "writeNextNode failed..." << endl;
		return -1;
	}

	//6. 编码seckeyid
	ret = writeNextNode(mRespondMsg->secKeyId);
	if (0 != ret)
	{
		cout << "writeNextNode failed..." << endl;
		return -1;
	}

	//7. 编码结构体
	ret = packSequence(outData, len);
	if (0 != ret)
	{
		cout << "packSequence failed..." << endl;
		return -1;
	}

	//8. 传出

	//9. 释放内存
	freeSequence();

	return 0;
}

//解码函数
void * RespondCodec::msgDecode(char * inData, int inLen)
{
	int ret = -1;

	RespondMsg *pRespond = NULL;

	//1. 参数检查
	if (NULL == inData || inLen <= 0)
	{
		cout << "参数非法" << endl;
		return NULL;
	}

	//2. 解码结构体
	ret = unpackSequence(inData, inLen);
	if (0 != ret)
	{
		cout << "unpackSequence failed.." << endl;
		return NULL;
	}

	//3. 解码rv
	ret = readHeadNode(mRespondMsg->rv);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}


	//4. 解码clientId
	ret = readNextNode(mRespondMsg->clientId);
	if (0 != ret)
	{
		cout << "readNextNode failed.." << endl;
		return NULL;
	}


	//5. 解码serverId
	ret = readNextNode(mRespondMsg->serverId);
	if (0 != ret)
	{
		cout << "readNextNode failed.." << endl;
		return NULL;
	}

	//6. 解码r2
	ret = readNextNode(mRespondMsg->r2);
	if (0 != ret)
	{
		cout << "readNextNode failed.." << endl;
		return NULL;
	}

	//7. 解码secKeyId
	ret = readNextNode(mRespondMsg->secKeyId);
	if (0 != ret)
	{
		cout << "readNextNode failed.." << endl;
		return NULL;
	}

	//8. 传出 深拷贝
	pRespond = new RespondMsg;
	if (NULL == pRespond)
	{
		cout << "new RespondMsg failed..." << endl;
		return NULL;
	}
	memset(pRespond, 0, sizeof(RespondMsg));
	memcpy(pRespond, mRespondMsg, sizeof(RespondMsg));

	//9. 释放内存
	freeSequence();

	return pRespond;
}

int RespondCodec::msgMemFree(void ** data)
{
	//参数检查
	if (NULL == data || NULL == *data)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	delete ((RespondMsg*)*data);

	*data = NULL;

	return 0;
}
