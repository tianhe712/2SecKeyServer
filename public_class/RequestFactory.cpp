#include "RequestFactory.h"

RequestFactory::RequestFactory()
{
}

RequestFactory::~RequestFactory()
{
}

//创建对象的方法
Codec * RequestFactory::createCodec(void * arg)
{
	Codec *codec = NULL;

	if (NULL == arg)
	{
		//创建一个请求报文解码对象
		codec = new RequestCodec;
	}
	else
	{
		//创建一个请求报文编码对象
		codec = new RequestCodec(static_cast<RequestMsg*>(arg));
	}

	return codec;
}
