这篇博文大部分是杂项，有一点web类的题；大概分为做题和新知识两块，主要学习了杂项新的思路以及简单的脚本写法。
## 一、做题
#### 分解1
得到图片binwalk之后用dd分离，得到flag。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312152543490.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)
#### 下雨天
binwalk之后发现是gif，改后缀之后发现有一闪而过的东西，用stegsolve逐帧检查之后可得到 flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312153502294.png)![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312153518129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)

#### 分解2
binwalk分解即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312154826300.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)


#### 女神
直接将图片放入winhex即可

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312164313279.png)
#### 捉迷藏
用stegsolves打开即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312175027480.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)
#### 召唤神龙
下载之后用winhex查看，发现里面有一个rar文件，用binwalk分离，但是需要密码，而且用ARCHER打不开，再次放入winhex，发现文件头为jpg格式
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313202215417.png)
修改后缀得到一张动漫图片，结合提示可得flag：venusctf{llabnogard}

## 二、新知识
#### 雨中龙猫
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313152820759.png)
这个题让我学到了一个新思路，考虑【图片源码隐写】，即将图片
更改为txt模式，然后根据提示将*whalectf{*转换为base64在txt中进行查找，即在txt中查找“d2hhbGVjdGY=”，搜索不到则逐渐减少后边的字符，得到一串字符：d2hhbGVjdGZ7TG，用base64解码得到whalectf{L，可以看出是flag的一半。![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313153212537.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)然后再根据题目用相同的方法找另外一半，即将“py}”用base64进行编码，然后在txt中搜索得到另外一半编码过的flag：9uZ19tYW9faXNfaGFwcHl9
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313153711306.png)然后将两个字符串合在一起用base64解码即可.


#### word隐写
更改后缀为.docx  然后直接右键->字体->取消隐藏即可得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312193440847.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)
#### 鲸鱼日记
将图片binwalk之后发现得到的文件太多，所以用foremost，得到一个word和一个jpg，打开word看下有没有隐藏，果然有，取消隐藏得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313155820895.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)

#### 分解3
将图片放入binwalk中得到一个zip压缩文件，解压缩发现需要密码，想用ARCHER破解但是不知道密码的组成，直接暴力破解又太慢了。去了解了其他的zip文件密码破解方式，小总结一下，zip文件的密码破解方式大概有以下几种：
1.看属性
2.伪加密
  即对文件头的加密标志位数据进行修改，从而使该文件打开时被认为是加密文件，可以通过十六进制编辑器对文件头尾进行修改来修复zip，但是通常此类伪加密zip文件在Linux的kali中可直接打开；也可以使用ZipCenOp.jar来进行判断，解包后能打开则是伪加密。指令java -jar ZipCenOp.jar r xxx.zip；同样也可以使用这个对文件进行伪加密，指令java -jar ZipCenOp.jar e xxx.zip
3.已知密码类型或者部分信息可用ARCHER破解
4.明文攻击
  明文攻击是一种较为高效的攻击手段，大致原理是当你不知道一个zip的密码，但是你有zip中的一个已知文件（文件大小要大于12Byte）或者已经通过其他手段知道zip加密文件中的某些内容时，因为同一个zip压缩包里的所有文件都是使用同一个加密密钥来加密的，所以可以用已知文件来找加密密钥，利用密钥来解锁其他加密文件，可以将已知文件压缩成.zip文件，然后在ARCHER中填入相应的路径即可开始进行明文攻击
5.CRC32碰撞
  CRC本身是“冗余校验码”的意思，CRC32则表示会产生一个32bit（8位十六进制数）的校验值。在产生CRC32时，源数据块的每一位都参与了运算，因此即使数据块中只有一位发生改变也会得到不同的CRC32值，利用这个原理我们可以直接爆破出加密文件的内容。我觉得就是模拟文件中的内容然后和已知crc32进行比较，和第三种很像。
  
回到这个题，我当时压缩包解密没做出来，问了同学才知道是用十六进制编辑器直接分离文件得到一个hidden2.jpg，图上就是flag“不用密码找到flag”，害，毕竟隐写最基本的就是将两个文件用二进制连接拼在一起...
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200313162057902.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)

#### 追加数据
通过tweakpng(这个下载我弄了很长时间...)查看png的IDAT数据块(65524满)，发现第一个IDAT块的长度大于65524(数据块65524满)，但后面还有一个长度为193的IDAT块，然后结合题目判断flag可能存在于长度193的IDAT块中。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314114217359.png)
将图片放入winhex中然后对IDAT进行查找，然后将这块十六进制数据复制出来
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314121422471.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)然后这些是通过zlib方式压缩的不可读数据，所以可用下面脚本解压，

```python
#! /bin/bash/
import zlib
import binascii
IDAT='789CA552B911C3300C5B09D87FB99C65E2A11A17915328FC8487C0C7E17BCEF57CCFAFA27CAB749B8A8E3E754C4C15EF25F934CDFF9DD7C0D413EB7D9E18D16F15D2EB0B2BF1D44C6AE6CAB1664F11933436A9D0D8AA6B5A2D09BA785E58EC8AB264111C0330A148170B90DA0E582CF388073676D2022C50CA86B63175A3FD26AE1ECDF2C658D148E0391591C9916A795432FBDDF27F6D2B71476C6C361C052FAA846A91B22C76A25878681B7EA904A950E28887562FDBC59AF6DFF901E0DBC1AB'.decode('hex')#这是复制的十六进制数据
result = binascii.hexlify(zlib.decompress(IDAT))#binascii.hexlify()：将括号中的内容转换为二进制，然后用十六进制表示；zlib.decompress()：使用zlib.compress可以压缩字符串。使用zlib.decompress可以解压字符串。所以这一句是将IDAT解压后用十六进制表示。
bin = result.decode('hex')
print (bin)
print (len(bin))
```
得到如下所示内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314123317730.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)因为长度为1024=32*32，所以可以考虑二维码。

**用脚本生成二维码**
1.先安装配置基本内容
在windows命令提示符中依次输入：
->pip install image
最开始安装这个的时候老在报错，通过python -m pip install --upgrade pip升级版本解决
->pip install qrcode
->pip install pillow 
安装过程中老是出现警告信息，可以在安装包后加-i url(其他pip源)解决。指令：pip install pymysql -i url（ [其他pip源](https://blog.csdn.net/lsf_007/article/details/87931823?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task)）

但是安装之后进行编译还是提示
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314152823813.png)
但是查看的话又显示已经安装成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314151751619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)百度到解决这个问题要在安装的时候指定路径，但是复制路径过去又提示路径不存在...

最开始查的是“Requirement already satisfied:”后来再直接搜“No module named 'Image' ”才发现是**引用错误**，应该用“`from PIL import Image, ImageFont`”而不是“`import Image`”。这一点让我迷惑了挺长时间，没想到是引用错，还以为是安装问题...在反复卸载安装python...


2.写脚本
```python
#! /bin/bash/
from PIL import Image, ImageFont
MAX = 32
pic = Image.new('RGB',(MAX*9,MAX*9))
f = open('result.txt','r')
str = f.read()
i = 0
for y in range(0,MAX*9,9):
    for x in range(0,MAX*9,9):
        if(str[i] == '1'):
            for n in range(9):
                for j in range(9):
                    pic.putpixel([x+j,y+n],(0,0,0))
        else:
            for k in range(9):
                for l in range(9):
                    pic.putpixel([x+l,y+k],(255,255,255))
                    i = i+1

pic.show()
pic.save("flag.png")
f.close()

```
得到一个二维码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314201015771.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)
用QRcode扫描得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314201205482.png)
[PIL 中的 Image 模块](https://www.cnblogs.com/way_testlife/archive/2011/04/20/2022997.html)



*写完这个又想起来当初没做的bugku的几个web脚本题*

#### 秋名山老司机
先用pip install requests 导入requests库但是又开始报错
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020031416141369.png)
在pip后面 -i加上其他源可以解决
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200314162016670.png)
然后因为算式是在<div><div/>中间，所以用*正则表达式*来提前算式去除最后的等号问号和冒号，然后输出，并用post方式提交到网页中。

```python
import requests
import re
url = 'http://123.206.87.240:8002/qiumingshan/'
s = requests.Session()#Session()防止提交答案时算式更新
nr = s.get(url)#提取页面信息
ss = re.search(r'(\d+[+\-*])+(\d+)', nr.text).group()#正则表达式提取<div></div>之间的算式
result = eval(ss)
post = {'value': result}
print(s.post(url, data = post).text)#用post方式提交结果

```
得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020031420194360.png)
#### 速度要快
查看元素发现要用post方法上传一个margin值，但是不知道具体上传什么值，随便上传一个值，提示我再快一点...用bp抓包试一下，包头有一个base64加密的flag值，解码之后得到“跑的还不错，给你flag吧: Nzl0OTg1”，但是提交之后不对
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200315103128214.png)
多go几次发现这一串base64的值是会变的，所以可以写脚本自动传递，即将解码后的flag值作为margin用post上传，最后得到flag

```python
import requests
import base64
url="http://123.206.87.240:8002/web6/?http:%2f%2f123.206.87.240:8002%2fweb6%2f"
r=requests.session()
headers=r.get(url).headers#flag在消息头里
flag=base64.b64decode(headers['flag'])
flag=flag.decode()
key = base64.b64decode(flag.split(':')[1])#获得flag:后的值
data={'margin':key}
print (r.post(url,data).text)#post上传
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200315104731503.png)

#### cookies欺骗
打开网页是一行乱码，但是url中的filename=a2V5cy50eHQ=，base64解码之后是keys.txt，将base64码换为keys.txt再进行访问，出现空白页，将kyes.txt更换为index.php，还是空白页，将index.php编码为base64，line即行数随便填一个，比如5，得到一行代码，修改行数，代码也变化，所以用可脚本导出所有代码，然后进行代码审计。

```python
import requests
a=20
for i in range(a):
    url="http://123.206.87.240:8002/web11/index.php?line="+str(i)+"&filename=aW5kZXgucGhw" 
    s=requests.get(url)
    print (s.text)
```
得到代码如下：

```php
<?php
error_reporting(0);
$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");
$line=isset($_GET['line'])?intval($_GET['line']):0;
if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");
$file_list = array(
'0' =>'keys.txt',
'1' =>'index.php',
);
if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){
$file_list[2]='keys.php';
}
if(in_array($file, $file_list)){
$fa = file($file);
echo $fa[$line];
}
?>
```
根据代码可得，传参cookies：margin=margin即可
得到一个空白页面，查看元素得到flag

#### 普通的二维码(bugku)
扫描二维码没有得到有效信息，
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020031515035168.png)
放入winhex查看，发现最后一段数据与上面的不同，而且只有0-7，可以考虑八进制
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200315150453735.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)将数字复制放入txt文件
写脚本将其转化为ascll码

```php
f=open('11.txt')
temp=[]
while True:
    k=f.read(3)
    if k:
        temp.append(k)
    else:
        break
f.close()
for i in temp:
    num='0o'+i
    num=int(num,base=0)
    num=chr(num)
    print(num,end='')
```
运行即可得flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200315151850295.png)
#### 你从哪里来
打开网页发现询问你是不是从谷歌访问，伪造一个请求头即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200315111102890.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L05FTU9BTU8=,size_16,color_FFFFFF,t_70)
唉，快开学吧，在家网速好慢...效率也真的不高...
