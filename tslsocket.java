package improtant;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

public class tslsocket{
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    protected int Myself;
    protected byte[] Public_Key;
    protected int want_cipher_index;
    protected byte[] helloPackage;
    protected byte[] recvPackage;//the field that client and server both have

    protected Socket socket;
    protected key_pattern key_pattern_client;
    protected String cipher_suite;//the field that only client have

    protected Socket servers;
    protected ServerSocket serverSocket;
    protected key_pattern key_pattern_server;//the field that only server have

    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    final protected static byte[] salt1=new byte[]{1,5,7,6,41,85,63,7,89};
    final protected static byte[] info1="handshake-info".getBytes();//used for generating handshakeKey
    final protected static byte[] salt2=new byte[]{1,2,5,8,50,88,90,0,100};
    final protected static byte[] info2="application-info".getBytes();//used for generating applicationKey

    public tslsocket(int myself)throws IOException {
        Myself=myself;
        if(myself==0){//client
            socket=new Socket("127.0.0.1",5858);
            socket.setSoTimeout(100000);
            key_pattern_client=new key_pattern();
            cipher_suite="DES_3DES";
        }
        else if(myself==1){//server
            serverSocket=new ServerSocket(5858);
            key_pattern_server=new key_pattern();
        }
    }

    public byte[] hkdfExtract(byte[] salt, byte[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac=Mac.getInstance("HmacSHA256");
        SecretKeySpec Keyspec=new SecretKeySpec(salt,"HmacSHA256");
        mac.init(Keyspec);
        return mac.doFinal(password);
    }

    public byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac=Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpe=new SecretKeySpec(prk,"HmacSHA256");
        mac.init(secretKeySpe);
        byte[] result=new byte[length];
        int pos=0;
        byte[] digest=new byte[0];
        byte t=1;
        while(pos<result.length){
            mac.update(digest);
            mac.update(info);
            mac.update(t);
            digest=mac.doFinal();
            System.arraycopy(digest,0,result,pos,Math.min(digest.length,length-pos));
            pos+=digest.length;
            t++;
        }
        return result;
    }

    public byte[] createHkdfKey(byte[] password, byte[] info, byte[] salt, int KeySize) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk=hkdfExtract(salt,password);
        return hkdfExpand(prk,info,KeySize);
    }

    public byte[] hmac(Key key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac=Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] result=mac.doFinal(data);
        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte[] padding(byte[] input,String mode)
    {
        if (input==null)
            return null;
        byte[] ret = (byte[]) null;
        if (mode.equals("ENCRYPT")){//加密模式
            int p=16-input.length%16; // p：看最后要补多少位
            //System.out.println(p);
            ret=new byte[input.length + p]; // ret：新的 16 倍数组
            System.arraycopy(input,0,ret,0,input.length); // 原内容拷到新数组
            for (int i=0;i<p;i++){ // 最后 p 位填充内容也为 p，方便解密时删除相应位数，此循环改进建议见下文
                ret[input.length+i]=(byte)p;
            }
        }
        else{ // 解密模式
            int p=input[input.length-1]; // 从最后一位读出 p，即补的位数
            ret=new byte[input.length-p]; // 生成原数组大小的新数组
            System.arraycopy(input,0,ret,0,input.length-p); // 把补位前的内容还原
        }
        return ret;
    }

    public KeyPair genEDCHE() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPair pairA;
        KeyPairGenerator kpgen=KeyPairGenerator.getInstance("ECDH","BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        kpgen.initialize(ecSpec);
        pairA=kpgen.generateKeyPair();
        PublicKey ecPublicKey=(ECPublicKey)pairA.getPublic();
        Public_Key=ecPublicKey.getEncoded();
        return pairA;
    }

    public byte[] doAgreement(PrivateKey prvkey,byte[] pubkey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        KeyAgreement ka=KeyAgreement.getInstance("ECDH","BC");
        KeyFactory kf=KeyFactory.getInstance("ECDH","BC");
        X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(pubkey);
        PublicKey publicKey=kf.generatePublic(x509EncodedKeySpec);
        ka.init(prvkey);
        ka.doPhase(publicKey,true);
        byte[] pre_session_key=ka.generateSecret();
        return  pre_session_key;

    }

    public int byteToInt(byte[] src,int offset){
        int value;
        value=(int) ((src[offset+3] & 0xFF)
                | ((src[offset+2] & 0xFF)<<8)
                | ((src[offset+1] & 0xFF)<<16)
                | ((src[offset] & 0xFF)<<24));
        return value;
    }

    public byte[] intToByte(int src) throws IOException {
        ByteArrayOutputStream bobs=new ByteArrayOutputStream();
        DataOutputStream dos=new DataOutputStream(bobs);
        dos.writeInt(src);
        byte[] offset=bobs.toByteArray();
        return offset;
    }
    /* the whole process have five steps:
       step1: The client sends the client hello, which contains 32bytes random number, some params and the public key of ECDHE algorithm.
       step2: The server receives the package, send its 32bytes random number, public key and certificate to the client.
       (When both sides receive the public key, they each calculate the same private key as the pre-session-key,and the use two random
       numbers and pre-session-key to generate the handshakeKey and applicationKey, which are used respectively for the confirmation of
       handshake messages and encryption of subsequent conversations)
       step3: Then the server will use the handshakeKey to sign the handshake information just sent to the client to confirm the identity.
       step4: After verifying the certificate, the client also use the handshake key to sign the handshake information just sent to the server.
       step5: After all the above steps are over, client start send the file encrypted by applicationKey to the server.
     */

    public void clienthello() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, ClassNotFoundException, InvalidKeySpecException, InvalidKeyException, CertificateException, InterruptedException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {//client starts handshaking
        /*---------------------------------------------------------step1----------------------------------------------------------------------*/
        key_pattern_client.client_random=new byte[32];
        new SecureRandom().nextBytes(key_pattern_client.client_random);//generate the clientRandom of 32 bytes
        key_pattern_client.keyPair=genEDCHE();//generate the public key
        byte[] cipher_suite_byte=cipher_suite.getBytes();
        byte[] offset=intToByte(Public_Key.length);//the offset is the length of publicKey

        int len=Public_Key.length+cipher_suite_byte.length+offset.length+32;
        byte[] message=new byte[len];
        System.arraycopy(key_pattern_client.client_random,0,message,0,32);
        System.arraycopy(Public_Key,0,message,32,Public_Key.length);
        System.arraycopy(cipher_suite_byte,0,message,32+Public_Key.length,cipher_suite_byte.length);
        System.arraycopy(offset,0,message,32+Public_Key.length+cipher_suite_byte.length,offset.length);
        helloPackage=message;
        message=padding(message,"ENCRYPT");//align

        OutputStream outputStream=socket.getOutputStream();
        outputStream.write(message,0,message.length);
        System.out.println("Client hello done!");
        /*

                +---------------------+-----------+--------------+--------------+---------+
                | client_random(32B)  | PublicKey | Cipher_suite |  offset(4B)  |  align  |
                +---------------------+-----------+--------------+--------------+---------+

        /*-----------------------------------------------------step1 finish---------------------------------------------------------------------*/

        InputStream inputStream=socket.getInputStream();
        byte[] resmessage=new byte[1024*4];
        int Clen=inputStream.read(resmessage);
        byte[] clientRecv=new byte[Clen];
        System.arraycopy(resmessage,0,clientRecv,0,Clen);
        clientRecv=padding(clientRecv,"DECRYPT");
        recvPackage=clientRecv;

        key_pattern_client.server_random=new byte[32];
        System.arraycopy(clientRecv,0,key_pattern_client.server_random,0,32);
        want_cipher_index=byteToInt(clientRecv,32);
        if(want_cipher_index==1){
            System.out.println("Client: Server chooses 3DES");
        }
        else {
            System.out.println("Client: Server chooses DES");
        }

        int Coffset=byteToInt(clientRecv,36);
        byte[] Ckey_share_byte=new byte[Coffset];
        System.arraycopy(clientRecv,32+4+4,Ckey_share_byte,0,Coffset);//client get the public key of server
        key_pattern_client.pre_session_key=doAgreement(key_pattern_client.keyPair.getPrivate(),Ckey_share_byte);//Key negotiation generates a pre-session-key
        System.out.println("Client pre key: "+bytesToHex(key_pattern_client.pre_session_key));

        byte[] CA_verify=new byte[clientRecv.length-32-4-4-Coffset];
        System.arraycopy(clientRecv,32+4+4+Coffset,CA_verify,0,clientRecv.length-32-4-4-Coffset);//client get the certificate
        if(verifyCA(CA_verify)==true){
            byte[] pass=new byte[32+32+key_pattern_client.pre_session_key.length];
            System.arraycopy(key_pattern_client.client_random,0,pass,0,32);
            System.arraycopy(key_pattern_client.server_random,0,pass,32,32);
            System.arraycopy(key_pattern_client.pre_session_key,0,pass,64,key_pattern_client.pre_session_key.length);
            key_pattern_client.handshakeKey=createHkdfKey(pass,info1,salt1,64);//use the two random numbers and pre-session-key to generate
            System.out.println("client generates the handshakeKey: "+bytesToHex(key_pattern_client.handshakeKey));//handshakeKey
            key_pattern_client.applicationKey=createHkdfKey(pass,info2,salt2,64);
            System.out.println("client generates the applicationKey: "+bytesToHex(key_pattern_client.applicationKey));//applicationKey

            /*---------------------------------------------------------step4----------------------------------------------------------------------*/
            Key key=new SecretKeySpec(key_pattern_client.handshakeKey,"");
            byte[] recvmac=new byte[1024*4];
            int macLen=inputStream.read(recvmac);
            byte[] recvMacMeassage=new byte[macLen];
            System.arraycopy(recvmac,0,recvMacMeassage,0,macLen);
            //Compare the hash value sent by the server with the hash calculated by itself
            if(Arrays.equals(recvMacMeassage,hmac(key,recvPackage))){
                //success! Send the client hello's hash to the server
                System.out.println("Client: pass the checking! Starting send the hash...");
                byte[] hmac_client=hmac(key,helloPackage);
                outputStream.write(hmac_client,0,hmac_client.length);
                socket.shutdownInput();
                Thread.sleep(1000);
                sendApplicationData();
                socket.close();
            }else {
                //fail! Just close the socket
                System.out.println("Server's hash is not correct, exiting...");
                outputStream.close();
                inputStream.close();
                socket.close();
            }
        }else{//if the certificate fails the check, simply close the socket
            outputStream.close();
            inputStream.close();
            socket.close();
        }
        /*--------------------------------------------------------step4 finish--------------------------------------------------------------------*/
    }

    public void serverhello() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, ClassNotFoundException, InvalidKeySpecException, InvalidKeyException, CertificateException, InterruptedException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        servers=serverSocket.accept();
        key_pattern_server.server_random=new byte[32];
        new SecureRandom().nextBytes(key_pattern_server.server_random);//generate the clientRandom of 32 bytes

        InputStream inputStream=servers.getInputStream();
        byte[] recvmessage=new byte[1024];
        int len=inputStream.read(recvmessage);
        byte[] recv=new byte[len];
        System.arraycopy(recvmessage,0,recv,0,len);
        recv=padding(recv,"DECRYPT");//receive the client hello
        recvPackage=recv;

        key_pattern_server.client_random=new byte[32];
        System.arraycopy(recv,0,key_pattern_server.client_random,0,32);

        int offset=byteToInt(recv,recv.length-4);
        byte[] client_pub=new byte[offset];
        System.arraycopy(recv,32,client_pub,0,offset);//receive the public key of client

        key_pattern_server.keyPair=genEDCHE();
        //use the client's public key and own private key to generate the pre-session-key
        key_pattern_server.pre_session_key=doAgreement(key_pattern_server.keyPair.getPrivate(),client_pub);
        System.out.println("Server pre key: "+bytesToHex(key_pattern_server.pre_session_key));

        byte[] cipher_suite_get=new byte[recv.length-32-4-offset];
        System.arraycopy(recv,32+offset,cipher_suite_get,0,recv.length-32-4-offset);
        System.out.println("Server gets the cipher suite: "+new String(cipher_suite_get));

        /*---------------------------------------------------------step2----------------------------------------------------------------------*/
        //chose cipher suite randomly
        System.out.println("Server starts choosing the cipher suite...");
        Random random=new Random();
        want_cipher_index=(random.nextInt(100)%2==0)?1:0;
        if(want_cipher_index==1)System.out.println("Server choose 3DES");
        else System.out.println("Server choose DES");

        byte[] index=intToByte(want_cipher_index);//4byte
        byte[] Soffset=intToByte(Public_Key.length);
        byte[] CA=sendFile("server/TLS.crt");
        int Slen=32+index.length+Public_Key.length+Soffset.length+CA.length;
        byte[] serverHelloMes=new byte[Slen];

        System.arraycopy(key_pattern_server.server_random,0,serverHelloMes,0,32);
        System.arraycopy(index,0,serverHelloMes,32,index.length);
        System.arraycopy(Soffset,0,serverHelloMes,32+index.length,Soffset.length);
        System.arraycopy(Public_Key,0,serverHelloMes,32+index.length+Soffset.length,Public_Key.length);
        System.arraycopy(CA,0,serverHelloMes,32+index.length+Soffset.length+Public_Key.length,CA.length);
        helloPackage=serverHelloMes;
        serverHelloMes=padding(serverHelloMes,"ENCRYPT");

        OutputStream SoutputStream=servers.getOutputStream();
        SoutputStream.write(serverHelloMes,0,serverHelloMes.length);
        /*

                +---------------------+-----------+------------+-----------+-------------+-------+
                | server_random(32B)  | index(4B) | offset(4B) | PublicKey | certificate | align |
                +---------------------+-----------+------------+-----------+-------------+-------+

        /*---------------------------------------------------------step2 finish------------------------------------------------------------------*/

        Thread.sleep(1000);

        byte[] pass=new byte[32+32+key_pattern_server.pre_session_key.length];
        System.arraycopy(key_pattern_server.client_random,0,pass,0,32);
        System.arraycopy(key_pattern_server.server_random,0,pass,32,32);
        System.arraycopy(key_pattern_server.pre_session_key,0,pass,64,key_pattern_server.pre_session_key.length);
        key_pattern_server.handshakeKey=createHkdfKey(pass,info1,salt1,64);
        System.out.println("server generates the handshakeKey: "+bytesToHex(key_pattern_server.handshakeKey));
        key_pattern_server.applicationKey=createHkdfKey(pass,info2,salt2,64);
        System.out.println("client generates the applicationKey: "+bytesToHex(key_pattern_server.applicationKey));

        /*------------------------------------------------------------step3--------------------------___S--------------------------------------------*/
        Key key=new SecretKeySpec(key_pattern_server.handshakeKey,"");
        byte[] hmac_server=hmac(key,helloPackage);
        SoutputStream.write(hmac_server,0,hmac_server.length);

        System.out.println("server have sent the helloPackage's hash...");
        System.out.println("Server hello done!");
        /*---------------------------------------------------------step3 finish----------------------------------------------------------------------*/

        byte[] recvmac=new byte[1024*4];
        int macLen=inputStream.read(recvmac);
        byte[] recvMacMeassage=new byte[macLen];
        System.arraycopy(recvmac,0,recvMacMeassage,0,macLen);
        //Compare the hash value sent by the client with the hash calculated by itself
        if(Arrays.equals(recvMacMeassage,hmac(key,recvPackage))){
            System.out.println("Server: pass the checking! Waiting for the application data...");
            servers.shutdownOutput();//ready to receive the encrypted application data
            Thread.sleep(1000);
            receiveApplicationData();
            servers.close();
            serverSocket.close();
        }else{//fail check, just close the socket
            System.out.println("Client's hash is not correct, exiting...");
            SoutputStream.close();
            inputStream.close();
            servers.close();
            serverSocket.close();
        }
    }

    /*------------------------------------------------------------step5----------------------------------------------------------------------*/
    public void sendApplicationData() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        byte[] applicationData=sendFile("client/test.png");

        int offset=applicationData.length;
        byte[] off=intToByte(offset);

        Key key=new SecretKeySpec(key_pattern_client.applicationKey,"");
        byte[] mac=hmac(key,applicationData);

        int sendDataMesLen=off.length+applicationData.length+mac.length;
        byte[] sendDataMes=new byte[sendDataMesLen];
        System.arraycopy(off,0,sendDataMes,0,off.length);
        System.arraycopy(applicationData,0,sendDataMes,off.length,applicationData.length);
        System.arraycopy(mac,0,sendDataMes,off.length+applicationData.length,mac.length);
        sendDataMes=padding(sendDataMes,"ENCRYPT");//align
        OutputStream outputStream=socket.getOutputStream();
        if(want_cipher_index==0){//DES
            int length=encryptDes(sendDataMes).length;
            outputStream.write(encryptDes(sendDataMes),0,length);
            System.out.println("Client: Sent the applicationData "+length+" bytes successfully!");
        }else {//3DES
            int length=encrypt3Des(sendDataMes).length;
            outputStream.write(encrypt3Des(sendDataMes),0,encrypt3Des(sendDataMes).length);
            System.out.println("Client: Sent the applicationData "+length+" bytes successfully!");
        }
        outputStream.close();
    }

    /*

                +------------+------------------+-----+-------+
                | offset(4B) | Application data | mac | align |   offset is the length of application data
                +------------+------------------+-----+-------+
                 \_________________encrypted_________________/
    */

    public void receiveApplicationData() throws IOException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InterruptedException {
        InputStream inputStream=servers.getInputStream();
        byte[] recvDataMes=new byte[1024*300];
        byte[] data=new byte[1024*300];
        int dataLen=0;
        int index=0;
        while(dataLen!=-1){//发送大图片时发现一次收不完，于是while循环，read多次，index是真正收到有效字节数
            dataLen=inputStream.read(data);
            if(dataLen!=-1)System.arraycopy(data,0,recvDataMes,index,dataLen);
            else break;
            index+=dataLen;
        }

        byte[] recvData=new byte[index];
        System.arraycopy(recvDataMes,0,recvData,0,index);
        System.out.println("Server: received applicationData "+index+" bytes successfully!");
        if(want_cipher_index==1){
            recvData=decrypt3Des(recvData);
        }else {
            recvData=decryptDes(recvData);
        }
        recvData=padding(recvData,"DECRYPT");
        int offset=byteToInt(recvData,0);
        byte[] applicationDataRecv=new byte[offset];
        byte[] mac=new byte[recvData.length-4-offset];
        System.arraycopy(recvData,4,applicationDataRecv,0,offset);
        System.arraycopy(recvData,4+offset,mac,0,recvData.length-4-offset);
        Key key=new SecretKeySpec(key_pattern_server.applicationKey,"");
        if(Arrays.equals(mac,hmac(key,applicationDataRecv))){
            FileOutputStream fileOutputStream=new FileOutputStream("server/gettest.png");
            fileOutputStream.write(applicationDataRecv,0,applicationDataRecv.length);
            fileOutputStream.close();
        }else {
            System.out.println("ERROR: application's mac can't match the data!");
            return;
        }
    }
    /*------------------------------------------------------------step5 finish----------------------------------------------------------------------*/

    public byte[] sendFile(String path) throws CertificateException, IOException {
        File file =new File(path);
        FileInputStream fileInputStream=new FileInputStream(file);
        int filesize=(int)file.length();
        byte[] FL=new byte[filesize];
        int alreadyRead=0;
        int lineReadNum=0;
        while(alreadyRead<filesize&&(lineReadNum=fileInputStream.read(FL,alreadyRead,filesize-alreadyRead))>=0){
            alreadyRead+=lineReadNum;
        }
        if(alreadyRead!=filesize){
            throw new IOException("could not completely read file "+file.getName());
        }
        fileInputStream.close();
        return FL;
    }

    public boolean verifyCA(byte[] CA) throws IOException, CertificateException {
        FileOutputStream fileOutputStream = new FileOutputStream("client/TLS_server.crt");
        fileOutputStream.write(CA, 0, CA.length);
        FileInputStream fileInputStream = new FileInputStream("client/TLS_server.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate c = cf.generateCertificate(fileInputStream);
        X509Certificate t = (X509Certificate) c;
        Date TimeNow = new Date();
        fileInputStream.close();
        fileOutputStream.close();
        try {
            t.checkValidity(TimeNow);
            System.out.println("OK");
        } catch (CertificateExpiredException e) {
            System.out.println("expired");
            System.out.println(e.getMessage());
            return false;
        } catch (CertificateNotYetValidException e1) {
            System.out.println("no valid");
            System.out.println(e1.getMessage());
            return false;
        }
        PublicKey pbk = c.getPublicKey();
        try {
            c.verify(pbk);
            System.out.println("CA pass");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public byte[] encryptDes(byte[] initial) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        DESKeySpec desKeySpec=new DESKeySpec(key_pattern_client.applicationKey);
        SecretKeyFactory secretKeyFactory=SecretKeyFactory.getInstance("DES");
        SecretKey secretKey=secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher=Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        return cipher.doFinal(initial);
    }

    public byte[] decryptDes(byte[] encrypt) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        DESKeySpec desKeySpec=new DESKeySpec(key_pattern_server.applicationKey);
        SecretKeyFactory secretKeyFactory=SecretKeyFactory.getInstance("DES");
        SecretKey secretKey=secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher=Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        return cipher.doFinal(encrypt);
    }

    public byte[] encrypt3Des(byte[] initial) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        DESedeKeySpec desKeySpec=new DESedeKeySpec(key_pattern_client.applicationKey);
        SecretKeyFactory secretKeyFactory=SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey=secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher=Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        return cipher.doFinal(initial);
    }

    public byte[] decrypt3Des(byte[] encrypt) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        DESedeKeySpec desKeySpec=new DESedeKeySpec(key_pattern_server.applicationKey);
        SecretKeyFactory secretKeyFactory=SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey=secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher=Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        return cipher.doFinal(encrypt);
    }
}
