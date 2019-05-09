/**
 * @author Taoyimin
 * @create 2019 05 06 17:31
 */
public class Main {
    public static void main(String[] args) throws Exception {
        //客户端代码
        String text = "hello server!";

        //随机生成16位aes密钥
        byte[] aesKey = SecureRandomUtil.getRandom(16).getBytes();
        System.out.println("生成的aes密钥:\n" + new String(aesKey));

        //使用aes密钥对数据进行加密
        String encryptText = AESCipher.encrypt(aesKey, text);
        System.out.println("经过aes加密后的数据:\n" + encryptText);

        //使用客户端私钥对aes密钥签名
        String signature = RSACipher.sign(Config.CLIENT_PRIVATE_KEY, aesKey);
        System.out.println("签名:\n" + signature);

        //使用服务端公钥加密aes密钥
        byte[] encryptKey = RSACipher.encrypt(Config.SERVER_PUBLIC_KEY, aesKey);
        System.out.println("加密后的aes密钥:\n" + new String(encryptKey));

        //客户端发送密文、签名和加密后的aes密钥
        System.out.println("\n************************分割线************************\n");
        //接收到客户端发送过来的signature encrypt_key encrypt_text

        //服务端代码
        //使用服务端私钥对加密后的aes密钥解密
        byte[] aesKey1 = RSACipher.decrypt(Config.SERVER_PRIVATE_KEY, encryptKey);
        System.out.println("解密后的aes密钥:\n" + new String(aesKey1));

        //使用客户端公钥验签
        Boolean result = RSACipher.checkSign(Config.CLIENT_PUBLIC_KEY, aesKey1, signature);
        System.out.println("验签结果:\n" + result);

        //使用aes私钥解密密文
        String decryptText = AESCipher.decrypt(aesKey1, encryptText);
        System.out.println("经过aes解密后的数据:\n" + decryptText);
    }
}
