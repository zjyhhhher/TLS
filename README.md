# TLS
TLS的简单实现：PJ的整体思路是在TCP socket的基础上构建TLS socket，实现TLS的握手过程以及发送信息的加密过程。在main函数中分别开了两个线程分别执行client和server的代码。总体由以下5个步骤组成。

## STEP 1
第一步是 client 端发送 client hello 到服务器端，client hello 的报文由一个 32 字节的随机数（client_random）,客户端 ECDHE 密钥协商算法的公钥，可供服务器选择的密码套件，offset偏移量组成（offset 为公钥的长度）。并且为了规范报文格式，将报文长度进行对齐，使得报文字节数为 16 的整数倍，所以报文的整体结构如下图：
![image](https://github.com/zjyhhhher/TLS/assets/105298348/d1dea1e7-63ce-4c81-800d-333df75e73bf)

同时引入TLS1.3的思想，使用BouncyCastle库中的椭圆曲线密钥协商算法（ECDHE），该算法相比于Deffie-Hellman算法具有更快的运算速度以及向前安全性。选择曲线 “secp256k1”。

## STEP 2
第二步为服务器在接收到用户端的client hello之后，发送一个32字节的随机数，ECDHE算法的服务器端公钥，选定的加密方式以及服务器端证书的过程。报文结构如下：
![image](https://github.com/zjyhhhher/TLS/assets/105298348/2798f9ca-692d-4147-8592-e796e5897368)
Certificate为jdk中的keytool工具所生成，以文件 “TLS.crt”的形式存储在TLS/server文件夹中。

在用户端，收到服务器发送的报文之后，首先会将报文拆解，得到server_random，由index得到服务器选择的加密方式，并由offset得到该长度的服务器公钥，最后提取出证书进行验证，验证通过进行后面的步骤，验证未通过，直接关闭套接字。

这时，client和server端均拥有client_random,server_random和pre-session-key这3个字节数组，这时客户和服务器将独自地，通过相同的方法（密钥导出函数），导出4个密钥。
这里，我们规定密钥导出函数是TLS1.3使用的HKDF函数，这是因为HKDF（基于HMAC的KDF）可以利用一些初始的密钥材料，从中派生出指定长度的一个或多个安全强度很大的密钥。这里依次生成了四个密钥
- 客户通信密钥Applicationkey
- 客户握手信息哈希密钥HandshakeKey
- 服务器通信密钥Applicationkey
- 服务器握手信息哈希密钥HandshakeKey

## STEP 3
Client端和server端分别用helloPackage和recvPackage两个byte数组保存第一步和第二步中双方自己发送的和接收到对方的报文。

这一步中server用刚才生成的handshakeKey和SHA256算法生成第二步中helloPackage报文的摘要，发送到client端。

## STEP 4
这一步中client接收到server发来的摘要，并用hmac函数为recvPackage计算hash。如果接收到的和自己计算的一样则验证通过，接下来同样对helloPackage计算hash后发送给服务器端。如果验证未通过，直接关闭套接字。

同样在服务器端收到client发来的摘要后也会以同样的方式进行验证，验证不通过直接关闭套接字。
## STEP 5
接下来就是真正进行有效数据的交换，程序中的模拟为client向server发送TLS/client文件夹下的 “test.png”。
报文格式：
![image](https://github.com/zjyhhhher/TLS/assets/105298348/eae02c19-921a-4e6b-8c41-04895ec2e5b2)

