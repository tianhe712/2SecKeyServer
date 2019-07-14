#pragma once

#include "Codec.h"

//请求报文结构体类型
struct RequestMsg
{
	//1 密钥协商  	//2 密钥校验; 	// 3 密钥注销
	int		cmdType;		// 报文类型 
	char	clientId[12];	// 客户端编号
	char	authCode[65];	// 认证码
	char	serverId[12];	// 服务器端编号 
	char	r1[64];			// 客户端随机数
};

//请求报文编解码类
class RequestCodec : public Codec
{
public:

	enum CmdType { NewOrUpdate = 1, Check, Revoke, View };

	//构造解码对象
	RequestCodec();
	//构造编码对象
	RequestCodec(RequestMsg* msg);
	//析构函数
	~RequestCodec();

	// 重写父类函数
	//编码函数
	int msgEncode(char** outData, int &len);

	//解码函数
	void* msgDecode(char *inData, int inLen);

	//内存释放
	int msgMemFree(void **point);

private:
	RequestMsg *mRequestMsg;
};