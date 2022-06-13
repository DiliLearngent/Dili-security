## flask应用基本结构

### 1、初始化

所有的Flask程序都必须创建一个程序实例， 这个程序实例就是Flask类的对象。客户端把请求发送给Web服务器， 服务器再把请求发送给Flask程序实例， 然后由程序实例处理请求。

**创建程序实例：**

```
from flask import Flask
app = Flask(__name__)
```

此处的`__name__`是一个全局变量， 它的值是代码所处的模块或包的名字， Flask用这个参数决定程序的根目录， 以便稍后能找到相对于程序根目录的资源文件位置。

### 2、路由和视图函数

程序实例通过路由来处理请求——路由就是URL和处理请求的函数的映射——处理请求的函数就叫做视图函数

**定义路由：**

```
@app.route('/')
def index():
    return '<h1>hello world!<h1>'
```

把index()函数注册为程序根地址的处理程序：部署程序的服务器域名为www.example.com， 在浏览器中访问http://www.example.com后， 会触发服务器执行index()函数,返回值称作为响应

**url中包含可变部分的路由：**

```
@app.route('/user/<name>')
def user(name):
	return '<h1>hello,%s</h1>' %name
```

尖括号中的内容就是动态部分，任何能匹配静态部分的URL都会映射到这个视图函数， 调用视图函数时， Flask会将动态部分作为参数传入函数。注意：路由中的动态部分默认类型是字符串， 不过也可以使用别的类型如：/user/<int: id>只会匹配动态片段id为整数的url。

### 3、启动服务器

Flask 应用自带 Web 开发服务器，通过 flask run 命令启动。这个命令在 FLASK_APP 环境变量指定的 Python 脚本中寻找应用实例。

Linux 和 macOS 用户执行下述命令启动 Web 服务器：

```
export FLASK_APP=app.py
flask run
```

Windows:

```
powershell: $env:FLASK_APP="app.py"
cmd: set FLASK_APP=app.py
```

服务器启动后便开始轮询，处理请求。直到按 Ctrl+C 键停止服务器，轮询才会停止

在浏览器中输入：http://localhost:5000/

另一种启动方式：

```
if __name__ == '__main__':
	app.run(debug=True)     #debug参数为True， 表示启用调试模式
```

### 4、命令行选项

执行`flask --help`

flask shell 命令在应用的上下文中打开一个 Python shell 会话

--host选项指Web 服务器在哪个网络接口上监听客户端发来的连接，默认是localhost

### 5、请求-响应循环

#### 应用和请求上下文

Flask 从客户端收到请求时，要让视图函数能访问一些对象，这样才能处理请求

```python
from flask import Flask,request
app = Flask(__name__)

@app.route('/')
def index():
    user_agent = request.headers.get('User_Agent')
    return '<p>Your browser is {}.</p>'.format(user_agent)

if __name__=="__main__":
    app.run(debug=True)
```

#### 请求委派

URL 映射是 URL 和视图函数之间的对应关系。Flask 使用 app.route 装饰器构建映射

在 Python shell 中审查为 app.py 生成的映射:

```
>>> from world import app
>>> app.url_map
Map([<Rule '/' (GET, HEAD, OPTIONS) -> index>,
 <Rule '/static/<filename>' (GET, HEAD, OPTIONS) -> static>,
 <Rule '/user/<name>' (GET, HEAD, OPTIONS) -> user>])
```

/ 和 /user/ 路由在应用中使用 app.route 装饰器定义。/static/ 路由是 Flask 添加的特殊路由，用于访问静态文件。

URL 映射中的 (HEAD, OPTIONS, GET) 是请求方法，由路由进行处理;即使不同的请求方法发送到相同的 URL 上时，也会使用不同的视图函数处理。HEAD 和 OPTIONS 方法由 Flask 自动处理

#### 响应

HTTP 响应中一个很重要的部分是状态码，Flask 默认设为 200，表明请求已被成功处理；如果视图函数返回的响应需要使用不同的状态码，可以把数字代码作为第二个返回值，添加到响应文本之后

```
@app.route('/')
def index():
    return '<h1>Bad Request</h1>', 400
```

如果不想返回一个元组，Flask 视图函数还可以返回一个响应对象。**make_response() **函数可接受 1 个、2 个或 3 个参数（和视图函数的返回值一样），然后返回一个等效的响应对象

比如设置cookie：

```
from flask import make_response
@app.route('/')
def index():
    response = make_response('<h1>cookie!</h1>')
    response.set_cookie('name','lsy')
    return response
```

#### 重定向

重定向的状态码通常是 302，在 Location 首部中提供目标 URL

**redirect**

```
from flask import redirect

@app.route('/')
def index():
    return redirect('http://www.example.com')
```

#### 处理错误

**abort**

```
from flask import abort

@app.route('/user/<id>')
def get_user(id):
    user = load_user(id)
    if not user:
        abort(404)
    return '<h1>Hello, {}</h1>'.format(user.name)
```

这个例子中，如果 URL 中动态参数 id 对应的用户不存在，就返回状态码 404；abort() 不会把控制权交还给调用它的函数，而是抛出异常

## 模块

视图函数有两个作用， 一个是业务逻辑一个是表现逻辑

用户在网站注册了一个新账号， 用户在表单中输入电子邮件地址和密码， 点击提交按钮， 服务器接收到包含用户输入的请求， 然后Flask把请求分发到处理注册请求的视图函数。 这个视图函数需要访问数据库， 添加新用户（业务逻辑）， 然后生成相应回送浏览器（表现逻辑）

两个模块在一起难以维护，需要将表现逻辑迁移至模板中

模板是包含响应文本的文件，其中包含用占位变量表示的动态部分，其具体值只在请求的上下文中才能知道。使用真实值替换变量，再返回最终得到的响应字符串，这一过程称为**渲染**。为了渲染模板，Flask 使用一个名为 Jinja2 的强大模板引擎。

### 如何使用模板

1. 如何使用模板
   + 模板放在`templates`文件夹下(固定)
   + 从`flask`中导入`render_template`函数
   + 在视图函数中，使用`render_template`函数，渲染模板。注意：只需要填写模板的名字，不需要填写`templates`这个文件夹的路径
2. 模板传参
   + 如果只有一个或者少量参数，直接在`render_template`函数中添加关键字参数就可以了
   + 如果有多个参数的时候，那么可以先把所有的参数放在字典中，然后在`render_template`中，
     使用两个星号，把字典转换成关键参数传递进去
3. 在模板中，如果要使用一个变量，语法是：`{{params}}`
4. 访问模型中的对象属性或者是字典，可以通过`{{params.property}}`的形式，或者是使用`{{params['age']}}`.

**示例代码**

test1.py

```python
#test1.py
from flask import Flask,render_template
app = Flask(__name__)

@app.route('/')
def index():
    class Person(object):
        name = 'lsy'
        age = 17

    p = Person()

    context = {
        'username':'lucy',
        'gender':'男',
        'age':17,
        'person':p,
        'websites':{
            'google':'www.google.com',
            'baidu':'www.baidu.com'
        }
    }
    return render_template('user.html',**context)

if __name__=='__main__':
    app.run(debug=True)
```

user.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>用户</title>
</head>
<body>
    输出动态信息
    <p>用户名:{{username}}</p>
    <p>性别:{{gender}}</p>
    <p>年龄:{{age}}</p>
    <p>朋友姓名:{{person.name}}</p>
    <p>朋友年龄:{{person.age}}</p>
    <p>百度:{{websites['baidu']}}</p>
    <p>谷歌:{{websites['google']}}</p>
</body>
</html>
```

### if的使用

语法：{% if xxx %}{% else %}{% endif %}

**示例代码**

login.py

```python
from flask import Flask,render_template
app = Flask(__name__)

@app.route('/<is_login>')
def login(is_login):
    if is_login == '1':
        user = {
            'username':'lucy',
            'age':19
        }
        return render_template('login.html',user=user)
    else:
        return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
```

login.html

```html
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset="utf-8">
    <title>登录</title>
</head>
<body>
    {% if user and user.age>18: %}
        <a href="#">{{user.username}}</a>
        <a href="#">注销</a>
    {% else %}
        <a href="#">登陆</a>
        <a href="#">注销</a>
    {% endif %}
</body>
</html>
```

### for循环

语法：

1.  字典的遍历，语法和`python`一样，可以使用`items()`、`keys()`、`values()`、`iteritems()`、`iterkeys()`、`itervalues()`
    `{% for k,v in user.items() %} <p>{{ k }}：{{ v }}</p> {% endfor %}`
2.  列表的遍历：语法和`python`一样。
    `{% for website in websites %} <p>{{ website }}</p> {% endfor %}`

**示例程序**

books.py

```python
from flask import Flask,render_template
app = Flask(__name__)

@app.route('/books')
def index():
    books = [
        {
            'name': u'西游记',
            'author': u'吴承恩',
            'price': 109
        },
        {
            'name': u'红楼梦',
            'author': u'曹雪芹',
            'price': 200
        },
        {
            'name': u'三国演义',
            'author': u'罗贯中',
            'price': 120
        },
        {
            'name': u'水浒传',
            'author': u'施耐庵',
            'price': 130
        }
    ]
    return render_template('books.html',books=books)

if __name__ == '__main__':
    app.run(debug=True)
```

books.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>books</title>
</head>
<body>
    <table>
        <thead>
            <th>书名</th>
            <th>作者</th>
            <th>价格</th>
        </thead>
        <tbody>
            {% for book in books %}
                <tr>
                    <td>{{book.name}}</td>
                    <td>{{book.author}}</td>
                    <td>{{book.price}}</td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
```

### 过滤器

过滤器可以处理变量，把原始的变量经过处理后再展示出来。作用的对象是变量

语法：`{{ avatar|default('xxx') }}`

1. default过滤器：如果当前变量不存在，这时候可以指定默认值。

2. length过滤器：求列表或者字符串或者字典或者元组的长度。

3. 常用过滤器

   abs(value)：返回一个数值的绝对值。示例：-1|abs
   default(value,default_value,boolean=false)：如果当前变量没有值，则会使用参数中的值来代替。示例：name|default('xiaotuo')——如果name不存在，则会使用xiaotuo来替代。boolean=False默认是在只有这个变量为undefined的时候才会使用default中的值，如果想使用python的形式判断是否为false，则可以传递boolean=true。也可以使用or来替换。
   escape(value)或e：转义字符，会将<、>等符号转义成HTML中的符号。示例：content|escape或content|e。
   first(value)：返回一个序列的第一个元素。示例：names|first
   last(value)：返回一个序列的最后一个元素。示例：names|last。

   length(value)：返回一个序列或者字典的长度。示例：names|length。
   join(value,d=u'')：将一个序列用d这个参数的值拼接成字符串。
   safe(value)：如果开启了全局转义，那么safe过滤器会将变量关掉转义。示例：content_html|safe。
   int(value)：将值转换为int类型。
   float(value)：将值转换为float类型。
   lower(value)：将字符串转换为小写。
   upper(value)：将字符串转换为小写。
   replace(value,old,new)： 替换将old替换为new的字符串。
   truncate(value,length=255,killwords=False)：截取length长度的字符串。
   striptags(value)：删除字符串中所有的HTML标签，如果出现多个空格，将替换成一个空格。
   trim：截取字符串前面和后面的空白字符。
   string(value)：将变量转换成字符串。
   wordcount(s)：计算一个长字符串中单词的个数。

**示例程序：**

filter.py

```python
from flask import Flask
from flask.templating import render_template
app = Flask(__name__)

@app.route('/comment')
def index():
    comments = [
        {
            'user':u'admin',
            'content':u'xxxx'
        },
        {
            'user':u'tester',
            'content':u'xxx'
        }
    ]
    return render_template('commnet.html',comments=comments)

if __name__=="__main__":
    app.run(debug=True)
```

comment.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>comment</title>
</head>
<!-- <img src="{{avatar|default('1.gif')}}" alt=""> -->
<body>
    <!-- 如果avatar这个变量不存在，就使用default过滤器提供的值 -->
    <img src="{{ avatar|default('https://www.baidu.com/img/PCtm_d9c8750bed0b3c7d089fa7d55720d6cf.png') }}" alt="">
    <hr>
    <!-- 计算长度 -->
    <p>评论数:{{comments|length}}</p>
    <ul>
        {% for comment in comments %}
            <li>
                <a href="#">{{comment.user}}</a>
                <p>{{comment.content}}</p>
            </li>
        {% endfor %}
    </ul>
</body>
</html>
```

### 继承和block

继承

作用：可以把一些公共的代码放在父模板中，避免每个模板写同样的代码

语法：{% extends 'base.html' %}

block实现：

作用：可以让子模板实现一些自己的需求。父模板需要提前定义好

注意：字模板中的代码，必须放在block块中

**示例程序**

app.py

```python
from flask import Flask,render_template
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/')
def login():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
```

base.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{% block title %}{% endblock %}</title>
        <style>
        .nav{
            background: #3a3a3a;
            height: 65px;
        }
        ul{
            overflow: hidden;
        }
        ul li{
            float: left;
            list-style: none;
            padding: 0 10px;
            line-height: 65px;
        }
        ul li a{
            color: #fff;
        }
    </style>
    {% block head %}{% endblock %}
</head>
<body>
<div class="nav">
    <ul>
        <li><a href="/">首页</a></li>
        <li><a href="/login">发布问答</a></li>
    </ul>
</div>
{% block main %}{% endblock %}
</body>
</html>
```

index.html

```html
{% extends 'base.html' %}

{% block head %}
<link rel="stylesheet" href="">
{% endblock %}

{% block title %}
登录
{% endblock %}

{% block main %}
<h1>这里是首页</h1>
{% endblock %}
```

login.html

```html
{% extends 'base.html' %}

{% block title %}
登陆
{% endblock %}

{% block main %}
<h1>这是登陆界面</h1>
{% endblock %}
```

### 使用Flask-Bootstrap集成Bootstrap

Bootstrap 是 Twitter 开发的一个开源 Web 框架，它提供的用户界面组件可用于创建整洁且具有吸引力的网页，而且兼容所有现代的桌面和移动平台 Web 浏览器。

安装

```
pip install flask-bootstrap
```

初始化：

```python
from flask import Flask,render_template
from flask_bootstrap import Bootstrap
app = Flask(__name__)
bootstrap = Bootstrap(app)
```

**示例程序**

app.py

```python
from flask import Flask,render_template
from flask_bootstrap import Bootstrap
app = Flask(__name__)
bootstrap = Bootstrap(app)

@app.route('/user/<name>')
def user(name):
    return render_template('user.html',name=name)
    
if __name__ == "__main__":
    app.run(debug=True)
```

templates/user.html：使用 Flask-Bootstrap 的模板

```html
{% extends "bootstrap/base.html" %}

{% block title %}
Flask
{% endblock %}

{% block navbar %}
<div class="navbar navbar-inverse" role="navigation">
    <div class="container">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle"
            data-toggle="collapse" data-target=".navbar-collapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">Flasky</a>
        </div>
        <div class="navbar-collapse collapse">
            <ul class="nav navbar-nav">
                <li><a href="/">Home</a></li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}
{% block content %}
<div class="container">
    <div class="page-header">
        <h1>hello,{{name}}</h1>
    </div>
</div>
{% endblock %}
```

Jinja2 中的 `extends` 指令从 Flask-Bootstrap 中导入 bootstrap/base.html，从而实现模板继承。Flask-Bootstrap 的基模板提供了一个网页骨架，引入了 Bootstrap 的所有 CSS 和 JavaScript 文件。

上面这个 user.html 模板定义了 3 个区块，分别名为 `title`、`navbar` 和 `content`。这些区块都是基模板提供的，可在衍生模板中重新定义。`title` 区块的作用很明显，其中的内容会出现在渲染后的 HTML 文档头部，放在 `<title>` 标签中。`navbar` 和 `content` 这两个区块分别表示页面中的导航栏和主体内容。

在这个模板中，`navbar` 区块使用 Bootstrap 组件定义了一个简单的导航栏。`content` 区块中有个 `<div>` 容器，其中包含一个页头。之前版本中的欢迎消息，现在就放在这个页头里。

### url链接

使用`url_for(视图函数名称)`可以反转成url

在模板中直接编写简单路由的 URL 链接不难，但对于包含可变部分的动态路由，在模板中构建正确的 URL 就很困难了。而且，直接编写 URL 会对代码中定义的路由产生不必要的依赖关系。如果重新定义路由，模板中的链接可能会失效。

flask 提供了 url_for() 辅助函数，它使用应用的 URL 映射中保存的信息生成 URL。

url_for() 函数最简单的用法是以视图函数名作为参数，返回对应的 URL。例如，在当前版本的 app.py 应用中调用 url_for('index') 得到的结果是 /，即应用的根 URL。调用 url_for('index', _external=True) 返回的则是绝对地址，在这个示例中是 http://localhost:5000/。

使用 url_for() 生成动态 URL 时，将动态部分作为关键字参数传入。例如，url_for('user', name='john', _external=True) 的返回结果是 http://localhost:5000/user/john。

传给 url_for() 的关键字参数不仅限于动态路由中的参数，非动态的参数也会添加到查询字符串中。例如，url_for('user', name='john', page=2, version=1) 的返回结果是 /user/ john?page=2&version=1

**示例代码**

将上面templates/user.html的a标签使用url_for

```
<li><a href="{{url_for('books')}}">Home</a></li>
```

### 加载静态文件

Web 应用不是仅由 Python 代码和模板组成。多数应用还会使用静态文件，例如模板中 HTML 代码引用的图像、JavaScript 源码文件和 CSS。

默认设置下，Flask 在应用根目录中名为 static 的子目录中寻找静态文件。如果需要，可在 static 文件夹中使用子文件夹存放文件。服务器收到映射到 static 路由上的 URL 后，生成的响应包含文件系统中对应文件里的内容。

1. 语法：`url_for('static',filename='路径')`
2. 可以加载`css`文件，可以加载`js`文件，还有`image`文件

加载CSS文件：

```
<link rel="stylesheet" href="{{ url_for('static',filename='css/index.css') }}"> 
```

加载JS文件：

```
<script src="{{ url_for('static',filename='js/index.js') }}"></script> 
```

加载图片文件：

```
<img src="{{ url_for('static',filename='images/zhiliao.png') }}" alt="">
```

## 表单

### 安装扩展库

```
pip install flask-wtf
```

### 配置

```
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
```

`app.config` 字典可用于存储 Flask、扩展和应用自身的配置变量

之所以配置密钥是因为防止CSRF攻击

### 第一步：表单类

使用 Flask-WTF 时，在服务器端，每个 Web 表单都由一个继承自 `FlaskForm` 的类表示。这个类定义表单中的一组字段，每个字段都用对象表示。字段对象可附属一个或多个**验证函数**。验证函数用于验证用户提交的数据是否有效。

```python
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')
```

这个表单中的字段都定义为类变量，而各个类变量的值是相应字段类型的对象。在这个示例中，`NameForm` 表单中有一个名为 `name` 的文本字段和一个名为 `submit` 的提交按钮。`StringField` 类表示属性为 `type="text"` 的 HTML `<input>` 元素。`SubmitField` 类表示属性为 `type="submit"` 的 HTML `<input>` 元素。字段构造函数的第一个参数是把表单渲染成 HTML 时使用的标注（label）。

`StringField` 构造函数中的可选参数 `validators` 指定一个由验证函数组成的列表，在接受用户提交的数据之前验证数据。验证函数 `DataRequired()` 确保提交的字段内容不为空。

`FlaskForm` 基类由 Flask-WTF 扩展定义，所以要从 `flask_wtf` 中导入。然而，字段和验证函数却是直接从 WTForms 包中导入的。

如果用户提交表单之前没有输入名字，那么 `DataRequired()` 验证函数会捕获这个错误

**表：WTForms支持的HTML标准字段**

| 字段类型              | 说明                                    |
| :-------------------- | :-------------------------------------- |
| `BooleanField`        | 复选框，值为 `True` 和 `False`          |
| `DateField`           | 文本字段，值为 `datetime.date` 格式     |
| `DateTimeField`       | 文本字段，值为 `datetime.datetime` 格式 |
| `DecimalField`        | 文本字段，值为 `decimal.Decimal`        |
| `FileField`           | 文件上传字段                            |
| `HiddenField`         | 隐藏的文本字段                          |
| `MultipleFileField`   | 多文件上传字段                          |
| `FieldList`           | 一组指定类型的字段                      |
| `FloatField`          | 文本字段，值为浮点数                    |
| `FormField`           | 把一个表单作为字段嵌入另一个表单        |
| `IntegerField`        | 文本字段，值为整数                      |
| `PasswordField`       | 密码文本字段                            |
| `RadioField`          | 一组单选按钮                            |
| `SelectField`         | 下拉列表                                |
| `SelectMultipleField` | 下拉列表，可选择多个值                  |
| `SubmitField`         | 表单提交按钮                            |
| `StringField`         | 文本字段                                |
| `TextAreaField`       | 多行文本字段                            |

**表：WTForms验证函数**

| 验证函数        | 说明                                                   |
| :-------------- | :----------------------------------------------------- |
| `DataRequired`  | 确保转换类型后字段中有数据                             |
| `Email`         | 验证电子邮件地址                                       |
| `EqualTo`       | 比较两个字段的值；常用于要求输入两次密码进行确认的情况 |
| `InputRequired` | 确保转换类型前字段中有数据                             |
| `IPAddress`     | 验证 IPv4 网络地址                                     |
| `Length`        | 验证输入字符串的长度                                   |
| `MacAddress`    | 验证 MAC 地址                                          |
| `NumberRange`   | 验证输入的值在数字范围之内                             |
| `Optional`      | 允许字段中没有输入，将跳过其他验证函数                 |
| `Regexp`        | 使用正则表达式验证输入值                               |
| `URL`           | 验证 URL                                               |
| `UUID`          | 验证 UUID                                              |
| `AnyOf`         | 确保输入值在一组可能的值中                             |
| `NoneOf`        | 确保输入值不在一组可能的值中                           |

### 第二步：把表单渲染成HTML

两种方法：

方法一：

假设视图函数通过 `form` 参数把一个 `NameForm` 实例传入模板，在模板中可以生成一个简单的 HTML 表单：

```python
<form method="POST">
    {{ form.hidden_tag() }}
    {{ form.name.label }} {{ form.name(id='my-text-field') }}
    {{ form.submit() }}
</form>
```

除了 `name` 和 `submit` 字段，这个表单还有个 `form.hidden_tag()` 元素。这个元素生成一个隐藏的字段，供 Flask-WTF 的 CSRF 防护机制使用。可添加id和class属性，供后面添加css样式

方法二：

使用 Flask-Bootstrap，上述表单可以用下面的方式渲染：

```python
{% import "bootstrap/wtf.html" as wtf %}
{{ wtf.quick_form(form) }}
```

`import` 指令的使用方法和普通 Python 代码一样，通过它可以导入模板元素，在多个模板中使用。导入的 bootstrap/wtf.html 文件中定义了一个使用 Bootstrap 渲染 Flask-WTF 表单对象的辅助函数。`wtf.quick_form()` 函数的参数为 Flask-WTF 表单对象，使用 Bootstrap 的默认样式渲染传入的表单。

### 第三步：在视图函数中处理表单

视图函数 `index()` 有两个任务：一是渲染表单，二是接收用户在表单中填写的数据

使用 `GET` 和 `POST` 请求方法处理 Web 表单:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    name = None
    form = NameForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
    return render_template('index.html', form=form, name=name)
```

`app.route` 装饰器中多出的 `methods` 参数告诉 Flask，在 URL 映射中把这个视图函数注册为 `GET` 和 `POST` 请求的处理程序。如果没指定 `methods` 参数，则只把视图函数注册为 `GET` 请求的处理程序。

这里有必要把 `POST` 加入方法列表，因为更常使用 `POST` 请求处理表单提交。表单也可以通过 `GET` 请求提交，但是 `GET` 请求没有主体，提交的数据以查询字符串的形式附加到 URL 中，在浏览器的地址栏中可见。基于这个以及其他多个原因，处理表单提交几乎都使用 `POST` 请求。

第二步中的示例代码：

index.html

```html
{% extends "base.html" %}
{% import "bootstrap/wtf.html" as wtf %}

{% block title %}Flasky{% endblock %}

{% block page_content %}
<div class="page-header">
    <h1>Hello, {% if name %}{{ name }}{% else %}Stranger{% endif %}!</h1>
</div>
{{ wtf.quick_form(form) }}
{% endblock %}

```

base.html

```html
{% extends "bootstrap/base.html" %}

{% block title %}Flasky{% endblock %}

{% block navbar %}
<div class="navbar navbar-inverse" role="navigation">
    <div class="container">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle"
             data-toggle="collapse" data-target=".navbar-collapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">Flasky</a>
        </div>
        <div class="navbar-collapse collapse">
            <ul class="nav navbar-nav">
                <li><a href="/">Home</a></li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}

{% block content %}
<div class="container">
    {% block page_content %}{% endblock %}
</div>
{% endblock %}
```

## 数据库

### 使用Flask-SQLAlchemy管理数据库

Flask-SQLAlchemy 是一个 Flask 扩展，简化了在 Flask 应用中使用 SQLAlchemy 的操作

安装：

```
pip install flask-sqlalchemy
```

在 Flask-SQLAlchemy 中，数据库使用 URL 指定。几种最流行的数据库引擎使用的 URL 格式如表 1 所示。

**表1：FLask-SQLAlchemy数据库URL**

| 数据库引擎             | URL                                              |
| :--------------------- | :----------------------------------------------- |
| MySQL                  | mysql://username:password@hostname/database      |
| Postgres               | postgresql://username:password@hostname/database |
| SQLite（Linux，macOS） | sqlite:////absolute/path/to/database             |
| SQLite（Windows）      | sqlite:///c:/absolute/path/to/database           |

在这些 URL 中，hostname 表示数据库服务所在的主机，可以是本地主机（localhost），也可以是远程服务器。数据库服务器上可以托管多个数据库，因此 database 表示要使用的数据库名。如果数据库需要验证身份，使用 username 和 password 提供数据库用户的凭据。

SQLite 数据库没有服务器，因此不用指定 hostname、username 和 password。URL 中的 database 是磁盘中的文件名。

应用使用的数据库 URL 必须保存到 Flask 配置对象的 `SQLALCHEMY_DATABASE_URI` 键中。Flask-SQLAlchemy 文档还建议把 `SQLALCHEMY_TRACK_MODIFICATIONS` 键设为 `False`，以便在不需要跟踪对象变化时降低内存消耗。其他配置选项的作用参阅 Flask-SQLAlchemy 的文档。

**示例：配置数据库**

```python
import os
from flask_sqlalchemy import SQLAlchemy
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
```

`db` 对象是 `SQLAlchemy` 类的实例，表示应用使用的数据库，通过它可获得 Flask-SQLAlchemy 提供的所有功能。

### 定义模型

Flask-SQLAlchemy 创建的数据库实例为模型提供了一个基类以及一系列辅助类和辅助函数

定义Role和User模型：

```python
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)

    def __repr__(self):
        return '<Role %r>' % self.name

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)

    def __repr__(self):
        return '<User %r>' % self.username
```

类变量 `__tablename__` 定义在数据库中使用的表名。

`db.Column` 类构造函数的第一个参数是数据库列和模型属性的类型

`db.Column`的配置选项：

**表2：最常用的SQLAlchemy列类型**

| 类型名         | Python类型           | 说明                                                  |
| :------------- | :------------------- | :---------------------------------------------------- |
| `Integer`      | `int`                | 普通整数，通常是 32 位                                |
| `SmallInteger` | `int`                | 取值范围小的整数，通常是 16 位                        |
| `BigInteger`   | `int` 或 `long`      | 不限制精度的整数                                      |
| `Float`        | `float`              | 浮点数                                                |
| `Numeric`      | `decimal.Decimal`    | 定点数                                                |
| `String`       | `str`                | 变长字符串                                            |
| `Text`         | `str`                | 变长字符串，对较长或不限长度的字符串做了优化          |
| `Unicode`      | `unicode`            | 变长 Unicode 字符串                                   |
| `UnicodeText`  | `unicode`            | 变长 Unicode 字符串，对较长或不限长度的字符串做了优化 |
| `Boolean`      | `bool`               | 布尔值                                                |
| `Date`         | `datetime.date`      | 日期                                                  |
| `Time`         | `datetime.time`      | 时间                                                  |
| `DateTime`     | `datetime.datetime`  | 日期和时间                                            |
| `Interval`     | `datetime.timedelta` | 时间间隔                                              |
| `Enum`         | `str`                | 一组字符串                                            |
| `PickleType`   | 任何 Python 对象     | 自动使用 Pickle 序列化                                |
| `LargeBinary`  | `str`                | 二进制 blob                                           |

**表3：最常用的SQLAlchemy列选项**

| 选项名        | 说明                                                         |
| :------------ | :----------------------------------------------------------- |
| `primary_key` | 如果设为 `True`，列为表的主键                                |
| `unique`      | 如果设为 `True`，列不允许出现重复的值                        |
| `index`       | 如果设为 `True`，为列创建索引，提升查询效率                  |
| `nullable`    | 如果设为 `True`，列允许使用空值；如果设为 `False`，列不允许使用空值 |
| `default`     | 为列定义默认值                                               |

Flask-SQLAlchemy 要求每个模型都定义**主键**

### 关系

**表4：常用的SQLAlchemy关系选项**

| 选项名          | 说明                                                         |
| :-------------- | :----------------------------------------------------------- |
| `backref`       | 在关系的另一个模型中添加反向引用                             |
| `primaryjoin`   | 明确指定两个模型之间使用的联结条件；只在模棱两可的关系中需要指定 |
| `lazy`          | 指定如何加载相关记录，可选值有 `select`（首次访问时按需加载）、`immediate`（源对象加载后就加载）、`joined`（加载记录，但使用联结）、`subquery`（立即加载，但使用子查询），`noload`（永不加载）和 `dynamic`（不加载记录，但提供加载记录的查询） |
| `uselist`       | 如果设为 `False`，不使用列表，而使用标量值                   |
| `order_by`      | 指定关系中记录的排序方式                                     |
| `secondary`     | 指定多对多关系中关联表的名称                                 |
| `secondaryjoin` | SQLAlchemy 无法自行决定时，指定多对多关系中的二级联结条件    |

示例：

```python
class Role(db.Model):
    # ...
    users = db.relationship('User', backref='role')

class User(db.Model):
    # ...
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
```

如上图所示，关系使用 `users` 表中的外键连接两行。添加到 `User` 模型中的 `role_id` 列被定义为外键，就是这个外键建立起了关系。传给 `db.ForeignKey()` 的参数 `'roles.id'` 表明，这列的值是 `roles` 表中相应行的 `id` 值。

`db.relationship()` 的第一个参数表明这个关系的另一端是哪个模型。如果关联的模型类在模块后面定义，可使用字符串形式指定。

`db.relationship()` 中的 `backref` 参数向 `User` 模型中添加一个 `role` 属性，从而定义反向关系。通过 `User` 实例的这个属性可以获取对应的 `Role` 模型对象，而不用再通过 `role_id` 外键获取。

多数情况下，`db.relationship()` 都能自行找到关系中的外键，但有时却无法确定哪一列是外键。例如，如果 User 模型中有两个或以上的列定义为 `Role` 模型的外键，SQLAlchemy 就不知道该使用哪一列。如果无法确定外键，就要为 `db.relationship()`提供额外的参数。

### 数据库操作

使用flask shell命令启动

#### 创建表

要让 Flask-SQLAlchemy 根据模型类创建数据库。`db.create_all()` 函数将寻找所有 `db.Model` 的子类，然后在数据库中创建对应的表

```
>>> from app import db
>>> db.create_all()
>>> db.drop_all()
```

更新现有数据库表的蛮力方式是先删除旧表再重新创建

#### 插入行

```
>>> from hello import Role, User
>>> admin_role = Role(name='Admin')
>>> mod_role = Role(name='Moderator')
>>> user_role = Role(name='User')
>>> user_john = User(username='john', role=admin_role)
>>> user_susan = User(username='susan', role=user_role)
>>> user_david = User(username='david', role=user_role)
```

模型的构造函数接受的参数是使用关键字参数指定的模型属性初始值。注意，`role` 属性也可使用，虽然它不是真正的数据库列，但却是一对多关系的高级表示。新建对象时没有明确设定 `id` 属性，因为在多数数据库中主键由数据库自身管理。现在这些对象只存在于 Python 中，还未写入数据库。因此，`id` 尚未赋值：

```
>>> print(admin_role.id)
None
```

对数据库的改动通过数据库**会话**管理，在 Flask-SQLAlchemy 中，会话由 `db.session` 表示。准备把对象写入数据库之前，要先将其添加到会话中：

```
>>> db.session.add(user_david)
>>> db.session.add(admin_role)
>>> db.session.add(mod_role)  
>>> db.session.add(user_role) 
>>> db.session.add(user_john)
>>> db.session.add(user_susan)
```

也可简写：

```
>>> db.session.add_all([admin_role, mod_role, user_role,
...     user_john, user_susan, user_david])
```

为了把对象写入数据库，我们要调用 `commit()` 方法**提交**会话：

```
db.session.commit()
```

再查看id：

```
>>> print(user_role.id)
3  
```

#### 修改行

```
>>> admin_role.name = 'Administrator'
>>> db.session.add(admin_role)
>>> db.session.commit()
```

#### 删除行

```
>>> db.session.delete(mod_role)
>>> db.session.commit()
```

#### 查询行

Flask-SQLAlchemy 为每个模型类都提供了 `query` 对象。最基本的模型查询是使用 `all()` 方法取回对应表中的所有记录：

```
>>> Role.query.all()
[<Role 'Administrator'>, <Role 'Moderator'>, <Role 'User'>]
>>> User.query.all()
[<User 'david'>, <User 'john'>, <User 'susan'>]
```

使用**过滤器**可以配置 `query` 对象进行更精确的数据库查询:

```
>>> User.query.filter_by(role=user_role).all()
[<User 'susan'>]
```

想查看 SQLAlchemy 为查询生成的原生 SQL 查询语句:

```
>>> str(User.query.filter_by(role=user_role))
'SELECT users.id AS users_id, users.username AS users_username, users.role_id AS users_role_id \nFROM users \nWHERE ? = users.role_id'
```

```
user_role = Role.query.filter_by(name='User').first()
```

`all()` 方法返回所有结果构成的列表，而 `first()` 方法只返回第一个结果，如果没有结果的话，则返回 `None`。因此，如果知道查询最多返回一个结果，就可以用这个方法。

**表5：常用的SQLAlchemy查询过滤器**

| 过滤器        | 说明                                                 |
| :------------ | :--------------------------------------------------- |
| `filter()`    | 把过滤器添加到原查询上，返回一个新查询               |
| `filter_by()` | 把等值过滤器添加到原查询上，返回一个新查询           |
| `limit()`     | 使用指定的值限制原查询返回的结果数量，返回一个新查询 |
| `offset()`    | 偏移原查询返回的结果，返回一个新查询                 |
| `order_by()`  | 根据指定条件对原查询结果进行排序，返回一个新查询     |
| `group_by()`  | 根据指定条件对原查询结果进行分组，返回一个新查询     |

在查询上应用指定的过滤器后，调用 `all()` 方法将执行查询，以列表的形式返回结果。除了 `all()` 方法之外，还有其他方法能触发查询执行。

**表6：最常用的SQLAlchemy查询执行方法**

| 方法             | 说明                                                         |
| :--------------- | :----------------------------------------------------------- |
| `all()`          | 以列表形式返回查询的所有结果                                 |
| `first()`        | 返回查询的第一个结果，如果没有结果，则返回 `None`            |
| `first_or_404()` | 返回查询的第一个结果，如果没有结果，则终止请求，返回 404 错误响应 |
| `get()`          | 返回指定主键对应的行，如果没有对应的行，则返回 `None`        |
| `get_or_404()`   | 返回指定主键对应的行，如果没找到指定的主键，则终止请求，返回 404 错误响应 |
| `count()`        | 返回查询结果的数量                                           |
| `paginate()`     | 返回一个 `Paginate` 对象，包含指定范围内的结果               |

加入了 `lazy='dynamic'` 参数，从而禁止自动执行查询。

完整的列表参见 SQLAlchemy 文档（[http://docs.sqlalchemy.org](http://docs.sqlalchemy.org/)）

### 在视图函数中操作数据库

视图函数：

```python
@app.route('/',methods=['POST','GET'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            db.session.commit()
            session['known'] = False
        else:
            session['known'] = True
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('index'))
    return render_template('index.html',form=form,name=session.get('name'),known=session.get('known',False))
```

index.html

```html
{% extends 'base.html' %}
{% import "bootstrap/wtf.html" as wtf %}

{% block title %}
Flask from
{% endblock %}

{% block page_content %}
<h1>Hello,
    {% if name %}
        {{name}}
    {% else %}
        Stranger!
    {% endif %}
</h1>
{% if not known %}
    <p>Nice to meet you!</p>
{% else %}
    <p>Happy to see you again!</p>
{% endif %}
{{wtf.quick_form(form)}}
{% endblock %}
```

## 集成python shell

若想把对象添加到导入列表中，必须使用 `app.shell_context_processor` 装饰器创建并注册一个 **shell 上下文处理器**

app.py中添加一个shell上下文：

```python
@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)
```

## 使用Flask-Migrate实现数据库迁移

更新表更好的方法是使用**数据库迁移**框架

### 创建迁移仓库

要在虚拟环境中安装 Flask-Migrate

```
pip install flask-migrate
```

初始化Flask-Migrate：

```
from flask_migrate import Migrate
...
migrate = Migrate(app, db)
```

为了开放数据库迁移相关的命令，Flask-Migrate 添加了 `flask db` 命令和几个子命令

创建 migrations 目录，所有迁移脚本都存放在这里：

`flask db init`

```
PS C:\code\pythonweb\flask-test> flask db init
Creating directory C:\code\pythonweb\flask-test\migrations ...  done
Creating directory C:\code\pythonweb\flask-test\migrations\versions ...  done
Generating C:\code\pythonweb\flask-test\migrations\alembic.ini ...  done
Generating C:\code\pythonweb\flask-test\migrations\env.py ...  done
Generating C:\code\pythonweb\flask-test\migrations\README ...  done
Generating C:\code\pythonweb\flask-test\migrations\script.py.mako ...  done
Please edit configuration/connection/logging settings in 'C:\\code\\pythonweb\\flask-test\\migrations\\alembic.ini' before proceeding.
```

### 创建迁移脚本

在 Alembic 中，数据库迁移用**迁移脚本**表示。脚本中有两个函数，分别是 `upgrade()` 和 `downgrade()`。`upgrade()` 函数把迁移中的改动应用到数据库中，`downgrade()` 函数则将改动删除。Alembic 具有添加和删除改动的能力，意味着数据库可重设到修改历史的任意一点。

使用 Flask-Migrate 管理数据库模式变化的步骤如下：

(1) 对模型类做必要的修改。

(2) 执行 `flask db migrate` 命令，自动创建一个迁移脚本。

(3) 检查自动生成的脚本，根据对模型的实际改动进行调整。

(4) 把迁移脚本纳入版本控制。

(5) 执行 `flask db upgrade` 命令，把迁移应用到数据库中。

`flask db migrate` 子命令用于自动创建迁移脚本：

```
PS C:\code\pythonweb\flask-test> flask db migrate -m 'add age from user'
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added column 'users.age'
Generating C:\code\pythonweb\flask-test\migrations\versions\5b6fd5a709a6_add_age_from_user.py ...  done
```

### 更新数据库

执行 `flask db upgrade` 命令，把迁移应用到数据库中

```
PS C:\code\pythonweb\flask-test> flask db upgrade
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 5b6fd5a709a6, add age from user
```

对第一个迁移来说，其作用与调用 `db.create_all()` 方法一样。但在后续的迁移中，`flask db upgrade` 命令能把改动应用到数据库中，且不影响其中保存的数据。