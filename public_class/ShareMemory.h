#pragma once

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>



//共享内存基类
class ShareMemory
{
public:
    //打开共享内存
    ShareMemory(int key);
    //打开共享内存
    ShareMemory(char *pathName);
    //创建共享内存
    ShareMemory(int key, int shmSize);
    //创建共享内存
    ShareMemory(char *pathName, int shmSize);
    //析构函数
    virtual ~ShareMemory();

    //关联共享内存
    void *mapShm();
    //解除关联共享内存
    int unMapShm();
    //删除共享内存
    int delShm();

private:
    //共享内存Id
    int mShmId = -1;
    //共享内存关联之后首地址
    void *mShmAddr = NULL;
};
