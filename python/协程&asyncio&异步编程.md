## 3.异步编程

### 3.1 事件循环

可以理解成为一个死循环，去检测并执行某些代码

```
# 伪代码
任务列表 = [任务1,任务2,任务3...]

while True:
	可执行的任务列表,已完成的任务列表 = 去任务列表中检查所有的任务，将‘可执行’和‘已完成’的任务返回
	
	for 就绪任务 in 可执行的任务列表:
		执行已就绪任务
	for 已完成的任务 in 已完成的任务列表:
		在任务列表中移除 已完成的任务
		
	如果 任务列表中的任务都已完成，则终止循环
```

```python
import asyncio

#去生成或获取一个事件循环
loop = asyncio.get_event_loop()
#将任务放到任务列表
loop.run_until_complete(任务)
```

### 3.2 快速上手

协程函数，定义函数时候`async def`函数名

协程对象，执行协程函数()得到的协程对象

```python
async def fun():
	pass
	
result = func()
```

注意：执行协程函数创建协程对象，函数内部代码不会执行

如果想要运行协程函数内部代码，必须要将协程对象交给事件循环来处理

```python
import asyncio
async def fun():
	pass
	
result = func()
#loop = asyncio.get_event_loop()
#loop.run_until_complete(result)
asyncio.run(result) #python3.7
```

### 3.3 await

await + 可等待的对象（协程对象、Future、Task对象——>IO等待）

示例1：

```python
import asyncio

async def func():
    print("111")
    response = await asyncio.sleep(2)
    print("结束",response)
    
asyncio.run(func())
```

示例2：

```python
import asyncio

async def others():
    print("start")
    await asyncio.sleep(2)
    print("end")
    return "返回值"
async def func():
    print("执行协程函数内部代码")
	#遇到IO操作挂起当前协程(任务),等IO操作完成之后再继续往下执行，当前协程挂起时，事件循环可以去执行其他协程(任务)
    response = await others()
    print("IO请求结束，结果为:",response)
    
asyncio.run(func())
```

示例3：

```python
import asyncio

async def others():
    print("start")
    await asyncio.sleep(2)
    print("end")
    return "返回值"
async def func():
    print("执行协程函数内部代码")
	#遇到IO操作挂起当前协程(任务),等IO操作完成之后再继续往下执行，当前协程挂起时，事件循环可以去执行其他协程(任务)
    response1 = await others()
    print("IO请求结束，结果为:",response1)
    
    response2 = await others()
    print("IO请求结束，结果为:",response2)
    
asyncio.run(func())
```

await就是等待对象的值得到结果之后再继续向下走

### 3.4 Task对象

在事件循环中添加多个任务的。

Task 对象被用来在事件循环中运行协程。

使用高层级的 [`asyncio.create_task()`](https://docs.python.org/zh-cn/3/library/asyncio-task.html#asyncio.create_task) (python3.7后)函数来创建 Task 对象，也可用低层级的 [`loop.create_task()`](https://docs.python.org/zh-cn/3/library/asyncio-eventloop.html#asyncio.loop.create_task) 或 [`ensure_future()`](https://docs.python.org/zh-cn/3/library/asyncio-future.html#asyncio.ensure_future) 函数。不建议手动实例化 Task 对象。

示例1：

```python
import asyncio

async def func():
    print("start")
    await asyncio.sleep(2)
    print("end")
    return "返回值"

aysnc def main():
    print("main开始")
    #创建Task对象，将当前执行func函数任务添加到事件循环
    task1 = asyncio.create_task(func())
    #创建Task对象，将当前执行func函数任务添加到事件循环
    task2 = asyncio.create_task(func())
    print("main结束")
    #当执行某协程遇到IO操作时，会自动化切换执行其他任务
    #此处的await是等待相对应的协程全部执行完毕并获取结果
    ret1 = await task1
    ret2 = await task2
    print(ret1,ret2)
asyncio.run(main())
```

示例2：

```python
import asyncio

async def func():
    print("start")
    await asyncio.sleep(2)
    print("end")
    return "返回值"

aysnc def main():
    print("main开始")
    task_list = [
        asyncio.create_task(func(),name='n1'),
        asyncio.create_task(func(),name='n2')
    ]
    print("main结束")
    
    done,pwnding = await asyncio.wait(task_list,timeout=None)
    print(done)
asyncio.run(main())
```

示例3：

```python
import asyncio

async def func():
    print("start")
    await asyncio.sleep(2)
    print("end")
    return "返回值"


task_list = [
    fucn(),
    func()
]
    
done,pwnding = asyncio.run(asyncio.wait(task_list))
print(done)
```

### 3.5 asyncio.Future对象

Task继承Future对象，Task对象内部await结果的处理基于Future对象来的



示例1：

```python
async def main():
	#获取当前事件循环
	loop = asyncio.get_running_loop()
	#创建一个任务（Future对象），这个任务什么都不干
	fut = loop.create_future()
	#等待任务最终结果(Future对象)，没有结果则会一直等下去
	await fut
asyncio.run(main())
```

示例2：

```python
import asyncio

async def set_after(fut):
    await asyncio.sleep(2)
    fut.set_result('666')
    
async def main():
    #获取当前事件循环
    loop = asyncio.get_running_loop()
    #创建一个任务(Future对象)，没绑定任何行为，则这个任务永远不知道什么时候结束
    fut = loop.create_future()
    #创建一个任务(Task对象)，绑定了set_after函数，函数内部2s秒后，会给fut赋值
    #即手动设置future任务的最终结果，那么fut就可以结束了
    
    #等待Future对象获取最终结果，否则一直循环等下去
    data = qwait fut
    print(data)
asyncio.run(main())
```

### 3.6 concurrent.futures.Future对象

使用线程池、进程池实现异步操作时用到的对象

```python
import time
from concurrent.futures import Future
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures.process import ProcessPoolExecutor

def func(value):
    time.sleep(1)
    print(value)
    return 123

#创建线程池
pool = ThreadPoolExecutor(max_workers=5)
#创建进程池
#pool = ProcessPoolExecutor(max_workers=5)
for i in range(10):
    fut = pool.submit(func,i)
    print fut
```

以后写代码可能会存在交叉时间。例如：crm项目80%都是基于异步编程+Mysql(不支持)【线程、进程做异步编程】

```python
import time
import asyncio
import concurrent.futures

def func1():
    #某个耗时操作
    time.sleep(2)
    return 'aa'

async def main():
    loop = asyncio.get_running_loop()
    
    #1. Run in the default loop's executor(默认的ThreadPoolExecutor)
    #第一步：内部会先调用ThreadPoolExecutor的submit方法去线程池中申请一个线程去执行func1函数，并且返回一个concurrent.futures.Future对象
    #第二步：调用asyncio.wrap_future将concurrent.futures.Future对象包装为asycio.Future对象
    #因为concurrent.futures.Future对象不支持await语法，所以需要包装为asycio.Future对象，才能使用
    fut = loop.run_in_executor(None,func1)
    result = await fut
    print('default thread pool',result)
    
    #2. Run in a custom thread pool:
    #with concurrent.futures.ThreadPoolExecutor() as pool:
    #    result = await loop.run_in_executor(pool,func)
    #    print('custom thread pool',result)
        
	#3. Run in a custom process pool:
    #with concurrent.futures。ProcessPoolExecutor() as pool:
    #    result = await loop.run_in_executor(pool,func1)
    #    print('custom process pool',result)
asyncio.run(main())
```

### 3.7 异步迭代器

迭代器：在其内部实现yield方法和next方法的对象。

**什么是异步迭代器**

实现了\_\_aiter\_\_()和\_\_anext_\_()方法的对象，\_\_anext\_\_必须返回一个awaitable对象。async_for会处理异步迭代器的\_\_anext\_\_()方法所返回的可等待对象，直到其引发一个StopAsyncIteration异常。由PEP 492引入。

**什么是异步可迭代对象**

可在async_for语句中被使用的对象，必须通过它的\_\_aiter\_\_()方法返回一个asynchronous_iterator（异步迭代器）. 这个改动由PEP 492引入。

```python
import asyncio

class Reader(object):
    """自定义异步迭代器(同时也是异步可迭代对象)"""
    
   def __init__(self):
    	self.count = 0
        
   async def readline(self):
    	#await asyncio.sleep(1)
        self.count += 1
        if self.count == 100:
            return None
        return self.count
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        val = await self.readline()
        if val == None:
            raise StopAsyncIteration
        return val
    
async def func():
    obj = Reader()
    async for item in obj:
        print(item)
        
asyncio.run(func())
```

### 3.8 异步上下文管理器

此种对象通过定义\_\_aenter\_\_()和\_\_aexit\_\_()方法来对async_with语句中的环境进行控制。由PEP 492引入

```python
import asyncio

class AsyncContextManager:
    def __init__(self):
        self.conn = conn
        
    async def do_something(self):
        #异步操作数据库
        return 666
    
    async def __aenter__(self):
        self.conn = await asyncio.sleep(1)
        return self
    
    async def __aexit__(self,exc_type,exc,tb):
        #异步关闭数据库链接
        await asyncio.sleep(1)

async def func():
	async with AsyncContextManager() as f:
    	result = await f.do_something()
   		print(result)
        
asyncio.run(func())
```

## 4.uvloop

是asyncio的事件循环的替代方案。事件循环效率>默认asyncio的事件循环

```
pip3 install uvloop
```

```
import asyncio
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy)

#编写asyncio的代码，与之前的代码一致
#内部的事件循环自动化会变为uvloop
asyncio.run(...)
```

注意：一个asgi->uvicorn内部使用的就是uvloop

## 5.实战案例

### 5.1 异步redis

在使用python代码操作redis时，链接/操作/断开都是网络IO

```
pip install aioredis
```

示例1：

```python
import asyncio
import aioredis

async def execute(address,password):
    print("开始执行",address)
    #网路IO操作：创建redis连接
    redis = await aioredis.create_redis(address,password=password)
    #网络IO操作：在redis中设置哈希值car，内部再设三个键值对，即：redis = {car:{key1:1,key2:2,key3:3}}
    await redis.hmset_dict('car',key1=1,key2=2,key3=3)
    #网络IO操作：去redis中获取值
    result = await redis.hgetall('car',encoding='utf-8')
    print(result)
    
    redis.close()
    #网络IO操作：关闭redis连接
    await redis.wait_closed()
    
    print("结束"，address)
    
asyncio.run(execute('redis://127.0.0.1:6379',"root!2345"))
```

示例2：

```python
import asyncio
import aioredis

async def execute(address,password):
    print("开始执行",address)
    #网路IO操作：先去连接1.1.1.1:6379,遇到IO则自动切换任务，去连接1.1.1.2:6379
    redis = await aioredis.create_redis(address,password=password)
    #网络IO操作：遇到IO会自动切换任务
    await redis.hmset_dict('car',key1=1,key2=2,key3=3)
    #网络IO操作：遇到IO会自动切换任务
    result = await redis.hgetall('car',encoding='utf-8')
    print(result)
    
    redis.close()
    #网络IO操作：遇到IO会自动切换任务
    await redis.wait_closed()
    
    print("结束"，address)
    
task_list = [
    execute('redis://1.1.1.1:6379',"root!2345"),
    execute('redis://1.1.1.2:6379',"root!2345")
]
asyncio.run(asyncio.wait(task_list))
```

### 5.2 异步MySQL

```
pip3 install aiomysql
```

示例1：

```python
import asyncio
import aiomysql

async def execute():
	#网络IO操作:连接MySQL
    conn = await aiomysql.connect(host='127.0.0.1',port=3306,user='root',password='123',db='mysql')
    #网络IO操作:创建CURSOR
    cur = await conn.cursor()
    #网络IO操作:执行SQL
    await cur.execute("SELECT Host,User FROM user")
    #网络IO操作:获取SQL结果
    result = await cur.fetchall()
    print(result)
    
    #网络IO操作:关闭连接
    await cur.close()
    conn.close()
    
asyncio.run(execute())
```

示例2：

```python
import asyncio
import aiomysql

async def execute(host,password):
    print("开始",host)
	#网络IO操作:先去连接1.1.1.1，遇到IO则自动切换任务，去连接1.1.1.2
    conn = await aiomysql.connect(host=host,port=3306,user='root',password=password,db='mysql')
    #网络IO操作:创建CURSOR
    cur = await conn.cursor()
    #网络IO操作:执行SQL
    await cur.execute("SELECT Host,User FROM user")
    #网络IO操作:获取SQL结果
    result = await cur.fetchall()
    print(result)
    
    #网络IO操作:关闭连接
    await cur.close()
    conn.close()
    print("结束",host)

task_list = [
    execute('redis://1.1.1.1:6379',"root!2345"),
    execute('redis://1.1.1.2:6379',"root!2345")
]
asyncio.run(asyncio.wait(task_list))
```

### 5.3 FastAPI框架

```
pip3 install fastapi

pip3 install uvicorn(asgi内部基于uvloop)
```

示例：luffy.py

```python
import asyncio
import uvicorn
from aioredis import Redis
from fastapi import FastAPI

app = FastAPI()

#创建一个redis连接池
REDIS_POOL = aioredis.ConnectionsPool('redis://1.1.1.1:6379',password="root123",minsize=1,maxsize=10)

@app.get("/")
def index():
	"""普通操作接口"""
    return {"message":"Hello world"}

@app.get("/red")
async def red():
    """异步操作接口"""
    print("请求来了")
    
    await asyncio.sleep(3)
    #连接池获取一个连接
    conn = await REDIS_POOL.acquire()
    redis = Redis(conn)
    
    #设置值
    await redis.hmset_dict('car',key1=1,key2=2,key3=3)
    
    #读取值
    result = await redis.hgetall('car',encoding='utf-8')
    
    #连接归还连接池
    REDIS_POOL.release(conn)
    
    return result

if __name__ == "__main__":
    uvicorn.run("luffy:app",host="127.0.0.1",post=5000,log_level="info")
```

### 5.4 爬虫

```
pip3 install aiohttp
```

示例：

```python
import aiohttp
import asyncio

async def fetch(session,url):
    print("发送请求:",url)
    async with session.get(url,verify_ssl=False) as response:
        text = await response.text()
        print("得到结果:",url,len(text))
        return text
    
async def main():
    async with aiohttp.ClientSession() as session:
        url_list = [
            'https://python.org',
            'https://www.baidu.com',
            'https://www.pythonav.com'
        ]
        tasks = [asyncio.create_task(fetch(session,url)) for url in url_list]
        
        done,pending = await asyncio.wait(tasks)
        
if __name__ == '__main__':
    asyncio.run(main())
```

# 总结

意义：通过一个线程利用其IO等待时间去做一些其他的事情。









