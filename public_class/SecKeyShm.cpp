#include "SecKeyShm.h"

#include <iostream>

using namespace std;


//打开共享内存
SecKeyShm::SecKeyShm(int key):ShareMemory(key)
{
}

//创建共享内存
SecKeyShm::SecKeyShm(int key, int maxNode):ShareMemory(key, maxNode * sizeof(NodeShmInfo)),mMaxNode(maxNode)
{
    //mMaxNode = maxNode;
}

//打开共享内存
SecKeyShm::SecKeyShm(char* pathName):ShareMemory(pathName)
{

}

//创建共享内存
SecKeyShm::SecKeyShm(char* pathName, int maxNode):ShareMemory(pathName, maxNode * sizeof(NodeShmInfo)), mMaxNode(maxNode)
{

}

//析构函数
SecKeyShm::~SecKeyShm()
{

}


//将网点密钥信息写入共享内存
int SecKeyShm::shmWrite(NodeShmInfo* pNodeInfo)
{
    int i = 0;

    void *addr = NULL;
    NodeShmInfo *tmp = NULL;
    NodeShmInfo tmpNode;

    //参数检查
    if (NULL == pNodeInfo)
    {
        return -1;  
    }

    //关联共享内存
    addr = mapShm();
    if (NULL == addr)
    {
        return -1; 
    }

    //第一种情形：如果共享内存中存在对应网点密钥信息，直接覆盖
    for (i = 0; i < mMaxNode; i++)
    {
        tmp = static_cast<NodeShmInfo*>(addr) + i;     
        if (strcmp(tmp->clientId, pNodeInfo->clientId) == 0 &&
            strcmp(tmp->serverId, pNodeInfo->serverId) == 0)
        {
            cout << "共享内存中存在对应网点密钥信息,现在就覆盖" << endl;        
            memcpy(tmp, pNodeInfo, sizeof(NodeShmInfo));
            break;
        }
    }

    //第二种情形：如果共享内存中不存在对应的网点密钥信息，找一个空白区域写
    if (i == mMaxNode)
    {
        memset(&tmpNode, 0, sizeof(tmpNode));
        for (i = 0; i < mMaxNode; i++)
        {
            tmp = static_cast<NodeShmInfo*>(addr) + i;
            if (memcmp(tmp, &tmpNode, sizeof(NodeShmInfo)) == 0) 
            {
                cout << "找到空白区域，现在就写共享内存" << endl; 
                memcpy(tmp, pNodeInfo, sizeof(NodeShmInfo));
                break;
            }
        }

        if (i == mMaxNode)
        {
            cout << "共享内存没有空白区域，请联系管理员" << endl; 
        }
    }

    //取消关联
    unMapShm();

	return 0;
}

//写空
int SecKeyShm::shmWrite(const char * clientId, const char * serverId, NodeShmInfo * pNodeInfo)
{
	int i = 0;

	void *addr = NULL;
	NodeShmInfo *tmp = NULL;
	NodeShmInfo tmpNode;

	//参数检查
	if (NULL == pNodeInfo)
	{
		return -1;
	}

	//关联共享内存
	addr = mapShm();
	if (NULL == addr)
	{
		return -1;
	}

	//第一种情形：如果共享内存中存在对应网点密钥信息，直接覆盖
	for (i = 0; i < mMaxNode; i++)
	{
		tmp = static_cast<NodeShmInfo*>(addr) + i;
		if (strcmp(tmp->clientId, clientId) == 0 &&
			strcmp(tmp->serverId, serverId) == 0)
		{
			cout << "共享内存中存在对应网点密钥信息,现在就覆盖" << endl;
			memcpy(tmp, pNodeInfo, sizeof(NodeShmInfo));
			break;
		}
	}

#if 0
	//第二种情形：如果共享内存中不存在对应的网点密钥信息，找一个空白区域写
	if (i == mMaxNode)
	{
		memset(&tmpNode, 0, sizeof(tmpNode));
		for (i = 0; i < mMaxNode; i++)
		{
			tmp = static_cast<NodeShmInfo*>(addr) + i;
			if (memcmp(tmp, &tmpNode, sizeof(NodeShmInfo)) == 0)
			{
				cout << "找到空白区域，现在就写共享内存" << endl;
				memcpy(tmp, pNodeInfo, sizeof(NodeShmInfo));
				break;
			}
		}

		if (i == mMaxNode)
		{
			cout << "共享内存没有空白区域，请联系管理员" << endl;
		}
	}
#endif

	//取消关联
	unMapShm();
	return 0;
}

//从共享内存中读取网点密钥信息
int SecKeyShm::shmRead(const char* clientId, const char* serverId, NodeShmInfo* pNodeInfo)
{
    int i = 0;

    void *addr = NULL;

    NodeShmInfo *tmp = NULL;

    //0. 参数检查
    if (NULL == clientId || NULL == serverId || NULL == pNodeInfo) 
    {
        cout << "参数非法" << endl; 
        return -1;
    }

    //1. 关联共享内存
    addr = mapShm();
    if (NULL == addr)
    {
        cout << "关联共享内存失败" << endl; 
        return -1;
    }

    //2. 读共享内存
    for (i = 0; i < mMaxNode; i++)
    {
        tmp = static_cast<NodeShmInfo*>(addr) + i;
        
        //比较
        if (strcmp(clientId, tmp->clientId) == 0 && strcmp(serverId, tmp->serverId) == 0)    
        {
            cout << "找到对应的网点密钥信息" << endl; 
            memcpy(pNodeInfo, tmp, sizeof(NodeShmInfo));
            break;
        }

    }

    if (i == mMaxNode)
    {
        cout << "共享内存中不存在对应的网点的密钥信息" << endl; 
    }

    //3. 取消关联
    unMapShm();

	return 0;
}


