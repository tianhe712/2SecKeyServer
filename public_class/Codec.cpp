#include "Codec.h"

//构造函数
Codec::Codec()
{
}

//析构函数
Codec::~Codec()
{
}

//报文编码函数
int Codec::msgEncode(char ** outData, int & len)
{
	return 0;
}

//报文解码函数
void * Codec::msgDecode(char * inData, int inLen)
{
	return nullptr;
}

//内存释放函数
int Codec::msgMemFree(void ** data)
{
	return 0;
}
