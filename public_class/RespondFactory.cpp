#include "RespondFactory.h"

//构造函数
RespondFactory::RespondFactory()
{
}

//析构函数
RespondFactory::~RespondFactory()
{
}

//创建编解码对象成员方法
//arg：编码的结构体地址或者NULL
//返回值： 对应编码或者解码对象
Codec * RespondFactory::createCodec(void * arg)
{
	Codec *codec = NULL;

	//创建一个解码对象
	if (NULL == arg)
	{
		codec = new RespondCodec;
	}
	else
	{
		//创建一个编码对象
		codec = new RespondCodec(static_cast<RespondMsg*>(arg));
	}

	return codec;
}
