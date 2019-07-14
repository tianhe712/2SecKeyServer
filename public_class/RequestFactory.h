#pragma once
#include "FactoryCodec.h"
#include "RequestCodec.h"

//请求报文工厂类  主要负责请求报文编码对象或者解码对象创建
class RequestFactory :public FactoryCodec
{
public:
	//构造函数
	RequestFactory();
	//析构函数
	~RequestFactory();
	//创建对象的方法
	Codec *createCodec(void *arg = NULL);
};

