#pragma once
#include "BaseASN1.h"
#include "ItcastLog.h"
#include <string>

//序列化类
class SequenceASN1  : public BaseASN1
{
public:
	//构造函数
    SequenceASN1();
	//析构函数
	~SequenceASN1();

    // 添加头结点
    int writeHeadNode(int iValue);
    int writeHeadNode(char* sValue, int len);
    // 添加后继结点
    int writeNextNode(int iValue);
    int writeNextNode(char* sValue, int len);

    // 读头结点数据
    int readHeadNode(int &iValue);
    int readHeadNode(char* sValue);
    // 读后继结点数据
    int readNextNode(int &iValue);
    int readNextNode(char* sValue);

    // 打包链表
    int packSequence(char** outData, int &outLen);
    // 解包链表
    int unpackSequence(char* inData, int inLen);

    // 释放链表
    void freeSequence(ITCAST_ANYBUF* node = NULL);

private:
	//指向链表的第一个节点
    ITCAST_ANYBUF* m_header = NULL;
	//指向链表的最后一个节点
	ITCAST_ANYBUF* m_next   = NULL;
	//中间临时节点
	ITCAST_ANYBUF* m_tmp   = NULL;
	//日志相关对象
	ItcastLog mLog;
};
