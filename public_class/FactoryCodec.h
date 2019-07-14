#pragma once

#include "Codec.h"

//工厂类基类
class FactoryCodec
{
public:
	FactoryCodec();
	virtual ~FactoryCodec();

	//负责创建对应类的对象
	virtual Codec *createCodec(void *arg = NULL);
};

