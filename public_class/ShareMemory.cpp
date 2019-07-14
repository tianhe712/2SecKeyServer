#include "ShareMemory.h"

//构造函数 打开共享内存
ShareMemory::ShareMemory(int key)
{
    mShmId = shmget(key, 0, 0);
    if (-1 == mShmId)
    {
        //写日志
        return; 
    }

}

//构造函数 打开共享内存
ShareMemory::ShareMemory(char *pathName)
{
    key_t key = -1;

    if (NULL == pathName)
    {
        //写日志 
        return;
    }

    //生成key
    key = ftok(pathName, 'X');
    if (-1 == key)
    {
        //写日志 
        return;
    }

    //打开共享内存
    mShmId = shmget(key, 0, 0);
    if (-1 == mShmId)
    {
        //写日志 
        return;
    }
}

//创建共享内存或者打开共享内存
ShareMemory::ShareMemory(int key, int shmSize)
{
    void *addr = NULL;

    if (shmSize <= 0)
    {
        //写日志 
        return;
    }

    //判断共享内存是否存在
    mShmId = shmget(key, shmSize, IPC_CREAT | IPC_EXCL | 0644); 
    if (-1 == mShmId)
    {
        //共享内存存在 
        mShmId = shmget(key, 0, 0);
    }
    else
    {
        //关联共享内存 
        addr = shmat(mShmId, NULL, 0);        
        if ((void*)-1 == addr)
        {
            //写日志
            return; 
        }

        memset(addr, 0, shmSize);

        //解除关联
        shmdt(addr); 
    }
}

//打开或者创建共享内存
ShareMemory::ShareMemory(char *pathName, int shmSize)
{
    key_t key = -1;

    void *addr = NULL;

    //检查参数
    if (NULL == pathName || shmSize <= 0)
    {
        //写日志 
        return;
    }

    //生成key
    key = ftok(pathName, 'X');
    if (-1 == key)
    {
        //写日志 
        return;
    }

    //判断共享内存是否存在
    mShmId = shmget(key, shmSize, IPC_CREAT | IPC_EXCL | 0644);
    if (-1 == mShmId)
    {
        //共享内存已经存在 
        mShmId = shmget(key, 0, 0);
    }
    else
    {
        //关联共享内存
        addr = shmat(mShmId, NULL, 0);     
        if ((void*)-1 == addr)
        {
            //写日志 
            return;
        }
        memset(addr, 0, shmSize);

        //解除关联
        shmdt(addr);
    }
}

//析构函数
ShareMemory::~ShareMemory()
{

}


//关联共享内存
void* ShareMemory::mapShm()
{
    mShmAddr = shmat(mShmId, NULL, 0);
    if ((void*)-1 == mShmAddr)
    {
        //写日志 
        return NULL;
    }

	return mShmAddr;
}

//解除关联共享内存
int ShareMemory::unMapShm()
{
    shmdt(mShmAddr);
    mShmAddr = NULL;

	return 0;
}

//删除共享内存
int ShareMemory::delShm()
{
    int ret = -1;

    ret = shmctl(mShmId, IPC_RMID, NULL);
    if (-1 == ret)
    {
        //写日志 
        return -1;
    }

	return 0;
}



