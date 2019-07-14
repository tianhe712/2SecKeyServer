#include "SequenceASN1.h"


//构造函数
SequenceASN1::SequenceASN1():BaseASN1()
{
}

//析构函数
SequenceASN1::~SequenceASN1()
{
}

//编码整型 第一个节点
int SequenceASN1::writeHeadNode(int iValue)
{
	ITCAST_INT ret = -1;

	ret = DER_ItAsn1_WriteInteger(iValue, &m_header);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_WriteInteger() err");
		return -1;
	}

	//m_next赋值
	m_next = m_header;

	return 0;
}

//编码字符串
int SequenceASN1::writeHeadNode(char * sValue, int len)
{
	ITCAST_INT ret = -1;

	ret = EncodeChar(sValue, len, &m_header);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func EncodeChar() err");
		return -1;
	}

	//m_next赋值
	m_next = m_header;

	return 0;
}

//不是链表的第一个节点
int SequenceASN1::writeNextNode(int iValue)
{
	ITCAST_INT ret = -1;

	ret = DER_ItAsn1_WriteInteger(iValue, &(m_next->next));
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_WriteInteger() err");
		return -1;
	}

	//m_next赋值
	m_next = m_next->next;
	return 0;
}

int SequenceASN1::writeNextNode(char * sValue, int len)
{
	ITCAST_INT ret = -1;

	ret = EncodeChar(sValue, len, &(m_next->next));
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func EncodeChar() err");
		return -1;
	}

	//m_next赋值
	m_next = m_next->next;

	return 0;
}

//解码链表的第一个节点
int SequenceASN1::readHeadNode(int & iValue)
{
	ITCAST_INT ret = -1;

	ret = DER_ItAsn1_ReadInteger(m_header, (ITCAST_UINT32 *)(&iValue));
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_ReadInteger() err");
		return -1;
	}

	//m_next赋值
	m_next = m_header->next;

	return 0;
}

//解码链表的第一个节点
int SequenceASN1::readHeadNode(char * sValue)
{
	ITCAST_INT ret = -1;
	
	ret = DER_ItAsn1_ReadPrintableString(m_header, &m_tmp);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_ReadPrintableString() err");
		return -1;
	}

	//拷贝数据
	memcpy(sValue, m_tmp->pData, m_tmp->dataLen);

	//释放内存
	DER_ITCAST_FreeQueue(m_tmp);
	m_tmp = NULL;

	//指向下一个节点
	m_next = m_header->next;

	return 0;
}

int SequenceASN1::readNextNode(int & iValue)
{
	ITCAST_INT ret = -1;

	ret = DER_ItAsn1_ReadInteger(m_next, (ITCAST_UINT32 *)(&iValue));
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_ReadInteger() err");
		return -1;
	}

	//m_next赋值
	m_next = m_next->next;

	return 0;
}

int SequenceASN1::readNextNode(char * sValue)
{
	ITCAST_INT ret = -1;

	ret = DER_ItAsn1_ReadPrintableString(m_next, &m_tmp);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_ReadPrintableString() err");
		return -1;
	}

	//拷贝数据
	memcpy(sValue, m_tmp->pData, m_tmp->dataLen);

	//指向下一个节点
	m_next = m_next->next;

	//释放内存
	DER_ITCAST_FreeQueue(m_tmp);
	m_tmp = NULL;

	return 0;
}

//编码结构体
int SequenceASN1::packSequence(char ** outData, int & outLen)
{
	ITCAST_INT ret = -1;

	char *out = NULL;

	ret = DER_ItAsn1_WriteSequence(m_header, &m_tmp);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_WriteSequence() err");
		return -1;
	}

	//分配空间
	out = new char[m_tmp->dataLen + 1];
	if (NULL == out)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "new char err");
		return -1;
	}
	memset(out, 0, m_tmp->dataLen + 1);

	//拷贝数据
	memcpy(out, m_tmp->pData, m_tmp->dataLen);

	*outData = out;
	outLen = m_tmp->dataLen;

	//释放内存
	DER_ITCAST_FreeQueue(m_tmp);
	m_tmp = NULL;

	return 0;
}

//解码结构体
int SequenceASN1::unpackSequence(char * inData, int inLen)
{
	ITCAST_INT ret = -1;

	//将char*转化ANYBUF类型
	ret = DER_ITCAST_String_To_AnyBuf(&m_tmp, (unsigned char *)inData, inLen);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ITCAST_String_To_AnyBuf() err");
		return -1;
	}

	//第一个参数：传入参数 ITCAST_ANYBUF类型   先将char*转化为ITCAST_ANYBUF
	//第二个参数：传出参数  得到链表
	ret = DER_ItAsn1_ReadSequence(m_tmp, &m_header);
	if (0 != ret)
	{
		mLog.Log(__FILE__, __LINE__, ItcastLog::ERROR, ret, "func DER_ItAsn1_ReadSequence() err");
		return -1;
	}

	//释放内存
	DER_ITCAST_FreeQueue(m_tmp);
	m_tmp = NULL;

	return 0;
}

//释放内存
void SequenceASN1::freeSequence(ITCAST_ANYBUF * node)
{
	//如果Node为空 就释放链表
	if (NULL == node)
	{
		DER_ITCAST_FreeQueue(m_header);
	}
	else
	{
		DER_ITCAST_FreeQueue(node);
	}
}
