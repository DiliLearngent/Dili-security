﻿﻿# CSRF

CSRF攻击的全称是跨站请求伪造(cross site request forgery)， 是一种对网站的恶意利用,一般以你的名义向第三方网站发送恶意请求。举个例子，你访问网站A一个链接A，这时你还没有退出网站A，然后访问网站B，网站B中的一个按钮或图片什么的内嵌了链接A，那么点击这些图片或按钮时就会发一个http请求访问链接A，同时也会带上浏览器的cookie，而服务端验证了cookie的数据无误后以为是用户在网站A上正确的操作。  



## 一、CSRF攻击原理

CSRF攻击攻击原理及过程如下：![](https://img-blog.csdnimg.cn/img_convert/31690c9f894def1d03290185d242125d.png)

1. 用户C打开浏览器，访问受信任网站A，输入用户名和密码请求登录网站A；
   2.在用户信息通过验证后，网站A产生Cookie信息并返回给浏览器，此时用户登录网站A成功，可以正常发送请求到网站A；

2. 用户未退出网站A之前，在同一浏览器中，打开一个TAB页访问网站B；

3. 网站B接收到用户请求后，返回一些攻击性代码，并发出一个请求要求访问第三方站点A；

4. 浏览器在接收到这些攻击性代码后，根据网站B的请求，在用户不知情的情况下携带Cookie信息，向网站A发出请求。网站A并不知道该请求其实是由B发起的，所以会根据用户C的Cookie信息以C的权限处理该请求，导致来自网站B的恶意代码被执行。

   　　



## 二、漏洞案例



**示例1：**

　　银行网站A，它以GET请求来完成银行转账的操作，如：http://www.mybank.com/Transfer.php?toBankId=11&money=1000

　　危险网站B，它里面有一段HTML的代码如下：

```markdown
<img src=http://www.mybank.com/Transfer.php?toBankId=11&money=1000>
```

　　首先，你登录了银行网站A，然后访问危险网站B，噢，这时你会发现你的银行账户少了1000块......

　　为什么会这样呢？原因是银行网站A违反了HTTP规范，使用GET请求更新资源。在访问危险网站B的之前，你已经登录了银行网站A，而B中的`<img>`以GET的方式请求第三方资源（这里的第三方就是指银行网站了，原本这是一个合法的请求，但这里被不法分子利用了），所以你的浏览器会带上你的银行网站A的Cookie发出Get请求，去获取资源“http://www.mybank.com/Transfer.php?toBankId=11&money=1000”，结果银行网站服务器收到请求后，认为这是一个更新资源操作（转账操作），所以就立刻进行转账操作......

**示例2：**

　　为了杜绝上面的问题，银行决定改用POST请求完成转账操作。

　　银行网站A的WEB表单如下：　　

```markdown

　　<form action="Transfer.php" method="POST">　　　　
　　 <p>ToBankId: <input type="text" name="toBankId" /></p>　　　　
　　 <p>Money: <input type="text" name="money" /></p>　　　　
　　 <p><input type="submit" value="Transfer" /></p>　　
　　</form>  

```



　　后台处理页面Transfer.php如下：

```
　<?php
　　　　session_start();
　　　　if (isset($_REQUEST['toBankId'] &&　isset($_REQUEST['money']))
　　　　{
　　　　  buy_stocks($_REQUEST['toBankId'],　$_REQUEST['money']);
　　　　}
　　?>
```

[![复制代码](https://common.cnblogs.com/images/copycode.gif)](javascript:void(0);)

　　危险网站B，仍然只是包含那句HTML代码：

```
<img src=http://www.mybank.com/Transfer.php?toBankId=11&money=1000>
```

　　和示例1中的操作一样，你首先登录了银行网站A，然后访问危险网站B，结果.....和示例1一样，你再次没了1000块～T_T，这次事故的原因是：银行后台使用了$_REQUEST去获取请求的数据，而$_REQUEST既可以获取GET请求的数据，也可以获取POST请求的数据，这就造成了在后台处理程序无法区分这到底是GET请求的数据还是POST请求的数据。在PHP中，可以使用$_GET和$_POST分别获取GET请求和POST请求的数据。在JAVA中，用于获取请求数据request一样存在不能区分GET请求数据和POST数据的问题。

　　**示例3：**

　　经过前面2个惨痛的教训，银行决定把获取请求数据的方法也改了，改用$_POST，只获取POST请求的数据，后台处理页面Transfer.php代码如下：

```markdown
　<?php
　　　　session_start();
　　　　if (isset($_POST['toBankId'] &&　isset($_POST['money']))
　　　　{
　　　　  buy_stocks($_POST['toBankId'],　$_POST['money']);
　　　　}
　　?>
```

　　然而，危险网站B与时俱进，它改了一下代码：

```markdown
<html>
　　<head>
　　　　<script type="text/javascript">
　　　　　　function steal()
　　　　　　{
          　　　　 iframe = document.frames["steal"];
　　     　　      iframe.document.Submit("transfer");
　　　　　　}
　　　　</script>
　　</head>

　　<body onload="steal()">
　　　　<iframe name="steal" display="none">
　　　　　　<form method="POST" name="transfer"　action="http://www.myBank.com/Transfer.php">
　　　　　　　　<input type="hidden" name="toBankId" value="11">
　　　　　　　　<input type="hidden" name="money" value="1000">
　　　　　　</form>
　　　　</iframe>
　　</body>
</html>
```



如果用户仍是继续上面的操作，很不幸，结果将会是再次不见1000块......因为这里危险网站B暗地里发送了POST请求到银行!

​        总结一下上面3个例子，CSRF主要的攻击模式基本上是以上的3种，其中以第1,2种最为严重，因为触发条件很简单，一个<img>就可以了，而第3种比较麻烦，需要使用JavaScript，所以使用的机会会比前面的少很多，但无论是哪种情况，只要触发了CSRF攻击，后果都有可能很严重。
　　
理解上面的3种攻击模式，其实可以看出，CSRF攻击是源于WEB的隐式身份验证机制！WEB的身份验证机制虽然可以保证一个请求是来自于某个用户的浏览器，但却无法保证该请求是用户批准发送的！

同学们也可以到DVWA平台模拟csrf攻击，它其中也有初级，进阶，高级的防护等级，就和上述3个例子差不多。



## 三、如何防御CSRF攻击

CSRF说白了就是利用浏览器的cookie的不安全性，跨站点的项目表发起伪装的请求，以达到攻击目的，一般会已下面三种方式防范：

1、cookie设置HttpOnly
cookie设置了HttpOnly属性后，其他站点就无法读取到本站点的cookie信息，避免cookie被其他网站截取后对其进行攻击

2、令牌
CSRF是伪造请求，那么就通过令牌token来验证是否是伪造的请求，前端访问服务器时都会以一种算法生成随机的token，服务器也已相同的算法验证token，因为攻击者无法生成token，服务器就可以拒绝这些非法请求来达到防范CSRF的攻击

3、Http Referer 客户端通过http协议访问服务器都会在http的头部带一个Referer属性，来告知客户端是谁，也就是http请求的原地址，因此如果是跨站点，那么这个头部的Referer信息肯定不是源地址，而是攻击者的跨站网点，服务器可以识别这个头部信息来确认发起的请求是否是合法的发起点



