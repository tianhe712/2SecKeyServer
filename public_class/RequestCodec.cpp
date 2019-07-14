#include "RequestCodec.h"

#include <iostream>

using namespace std;

//构造解码对象
RequestCodec::RequestCodec()
{
	//分配空间
	mRequestMsg = new RequestMsg;
	if (NULL == mRequestMsg)
	{
		cout << "RequestCodec new failed.." << endl;
		return;
	}

	//清零
	memset(mRequestMsg, 0, sizeof(RequestMsg));
}

//构造编码对象
RequestCodec::RequestCodec(RequestMsg * msg)
{
	//分配空间
	mRequestMsg = new RequestMsg;
	if (NULL == mRequestMsg)
	{
		cout << "RequestCodec new failed.." << endl;
		return;
	}

	//清零
	memset(mRequestMsg, 0, sizeof(RequestMsg));

	//拷贝数据
	memcpy(mRequestMsg, msg, sizeof(RequestMsg));
}

//析构函数
RequestCodec::~RequestCodec()
{
	delete mRequestMsg;
	mRequestMsg = NULL;
}

//编码
int RequestCodec::msgEncode(char ** outData, int & len)
{
	int ret = -1;

	//1. 参数检查
	if (NULL == outData)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	//2. 编码cmdType
	ret = writeHeadNode(mRequestMsg->cmdType);
	if (0 != ret)
	{
		cout << "writeHeadNode failed.." << endl;
		return -1;
	}

	//3. 编码clientId
	ret = writeNextNode(mRequestMsg->clientId, strlen(mRequestMsg->clientId));
	if (0 != ret)
	{
		cout << "writeNextNode failed.." << endl;
		return -1;
	}


	//4. 编码AuthCode
	ret = writeNextNode(mRequestMsg->authCode, strlen(mRequestMsg->authCode));
	if (0 != ret)
	{
		cout << "writeNextNode failed.." << endl;
		return -1;
	}

	//5. 编码serverId
	ret = writeNextNode(mRequestMsg->serverId, strlen(mRequestMsg->serverId));
	if (0 != ret)
	{
		cout << "writeNextNode failed.." << endl;
		return -1;
	}

	//6. 编码r1
	ret = writeNextNode(mRequestMsg->r1, strlen(mRequestMsg->r1));
	if (0 != ret)
	{
		cout << "writeNextNode failed.." << endl;
		return -1;
	}

	//7. 编码结构体 传出
	ret = packSequence(outData, len);
	if (0 != ret)
	{
		cout << "packSequence failed.." << endl;
		return -1;
	}

	//8. 释放链表内存
	freeSequence();
	
	return 0;
}

//解码函数
void * RequestCodec::msgDecode(char * inData, int inLen)
{
	int ret = -1;

	RequestMsg *mRequest = NULL;

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

	//3. 解码cmdType
	ret = readHeadNode(mRequestMsg->cmdType);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}

	//4. 解码clientId
	ret = readNextNode(mRequestMsg->clientId);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}

	//5. 解码authCode
	ret = readNextNode(mRequestMsg->authCode);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}

	//6. 解码serverId
	ret = readNextNode(mRequestMsg->serverId);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}

	//7. 解码r1
	ret = readNextNode(mRequestMsg->r1);
	if (0 != ret)
	{
		cout << "readHeadNode failed.." << endl;
		return NULL;
	}

	//8. 传出
	mRequest = new RequestMsg;
	if (NULL == mRequest)
	{
		cout << "new RequestMsg failed." << endl;
		return NULL;
	}
	memset(mRequest, 0, sizeof(RequestMsg));

	//拷贝数据
	memcpy(mRequest, mRequestMsg, sizeof(RequestMsg));

	//9. 释放链表内存
	freeSequence();

	return mRequest;
}

//释放结构体内存
int RequestCodec::msgMemFree(void ** point)
{
	//参数检查
	if (NULL == point || NULL == *point)
	{
		cout << "参数非法" << endl;
		return -1;
	}

	delete ((RequestMsg*)*point);

	*point = NULL;

	return 0;
}
