# python并发编程

## 三种方式

+ 多线程Thread
+ 多进程Process
+ 多协程Coroutine

## 怎样选择

### CPU密集型与IO密集型

+ CPU密集型计算

  IO完成时间短，需要大量的CPU计算

  如：压缩与解压缩、加密与解密、正则表达式的搜索

+ IO密集型计算

  CPU在等IO的读写操作，CPU的占用率较低

  如：文件处理程序、网络爬虫程序、读写数据库程序

## 三种方式的对比

+ 多进程Process（multiprocessing）

  优点：可以利用多核CPU并行计算

  缺点：占用资源最多，可启动数目比线程少

  适用于：CPU密集型计算

+ 多线程Thread（threading）

  优点：相比进程，更轻量级、占用资源少

  缺点：相比进程，多线程只能并发执行，不能利用多CPU；相比协程，启动数目有限制，占用内存资源，有线程切换开销

  适用于：IO密集型计算、同时运行的任务数目要求不多

+ 多协程Coroutine（asyncio）

  优点：内存开销最少，启动协程数目最多

  缺点：支持的库有限制，代码实现复杂

  使用于：IO密集型计算、需要超多任务运行、但有现成库支持的场景

**一个进程中可以启动N个线程，一个线程中可以启动N个协程**

## GIL

全局解释器锁，是计算器程序设计语言解释器用于同步线程的一种机制，它使得任何时刻仅有一个线程在执行

## python创建多线程的方法

+ 准备一个函数

  ```python
  def my_func(a,b):
  	do_craw(a,b)
  ```

+ 创建一个线程

  ```python
  import threading
  t = threading.Thread(target=my_func,args=(100,200))
  ```

+ 启动线程

  t.start()

+ 等待结束

  t.join()

### 多线程数据通信的queue.Queue

queue.Queue可以用于多线程之间的、**线程安全**的数据通信

+ 导入类库

  import queue

+ 创建Queue

  q = queue.Queue()

+ 添加元素

  q.put(item)

+ 获取元素

  item = q.get()

+ 查询状态

  + 查询元素的多少

    q.qsize()

  + 判断是否为空

    q.empty()

  + 判断是否已满

    q.full()

## lock用于解决线程安全问题

+ 用法一：try-finally模式

  ```python
  import threading
  
  lock = threading.Lock()
  
  lock.acquire()
  try:
  	#do something
  finally:
  	lock.release
  ```

+ 用法二：with模式

  ```python
  import threading
  
  lock = threading.Lock()
  
  with lock:
  	# do something
  ```

  

## 线程池

原理：新建线程系统需要分配资源，终止线程系统需要回收资源，如果可以重用线程，则可以省去系统对新建/回收的开销

ThreadPoolExecutor的使用方法：

```
from concurrent.futures import ThreadPoolExecutor,as_completed
```

+ 用法一：pool.map

  ```python
  with ThreadPoolExecutor() as pool:
  	results = pool.map(craw,urls)
  	for result in results:
  		print(result)
  ```

+ 用法二：pool.submit

  ```
  with ThreadPoolExecutor() as pool:
  	futures = [pool.submit(craw,url) for url in urls]
  	#1
  	for future in futures:
  		print(future.result())
  	#2按完成的顺序返回
  	for future in as_completed(futures):
  		print(future.result())
  ```

## 多进程

![](python并发img\进程与线程的对比.JPG)