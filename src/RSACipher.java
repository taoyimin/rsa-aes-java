import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Taoyimin
 * @create 2019 05 07 20:25
 */
public class RSACipher {
    /**
     * 加密方法
     *
     * @param publicKey 公钥
     * @param raw       待加密明文
     * @return 加密后的密文
     * @throws Exception
     */
    public static byte[] encrypt(String publicKey, byte[] raw) throws Exception {
        Key key = getPublicKey(publicKey);
        Cipher cipher = Cipher.getInstance(Config.RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] b1 = cipher.doFinal(raw);
        return Base64.encodeBase64(b1);
    }

    /**
     * 解密方法
     *
     * @param privateKey 私钥
     * @param enc        待解密密文
     * @return 解密后的明文
     * @throws Exception
     */
    public static byte[] decrypt(String privateKey, byte[] enc) throws Exception {
        Key key = getPrivateKey(privateKey);
        Cipher cipher = Cipher.getInstance(Config.RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        return cipher.doFinal(Base64.decodeBase64(enc));
    }

    /**
     * 获取公钥
     *
     * @param key 密钥字符串（经过base64编码）
     * @return 公钥
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 获取私钥
     *
     * @param key 密钥字符串（经过base64编码）
     * @return 私钥
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 签名
     *
     * @param privateKey 私钥
     * @param content    要进行签名的内容
     * @return 签名
     */
    public static String sign(String privateKey, byte[] content) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey.getBytes()));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(priKey);
            signature.update(content);
            byte[] signed = signature.sign();
            return new String(Base64.encodeBase64(signed));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验签
     *
     * @param publicKey 公钥
     * @param content   要验签的内容
     * @param sign      签名
     * @return 验签结果
     */
    public static boolean checkSign(String publicKey, byte[] content, String sign) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.decode2(publicKey);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            java.security.Signature signature = java.security.Signature.getInstance("SHA256WithRSA");
            signature.initVerify(pubKey);
            signature.update(content);
            return signature.verify(Base64.decode2(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        //客户端代码
        String text = "hello";
        //使用服务端公钥加密
        byte[] encryptText = RSACipher.encrypt(Config.SERVER_PUBLIC_KEY, text.getBytes());
        System.out.println("加密后:\n" + new String(encryptText));
        //使用客户端私钥签名
        String signature = RSACipher.sign(Config.CLIENT_PRIVATE_KEY, encryptText);
        System.out.println("签名:\n" + signature);

        //服务端代码
        //使用客户端公钥验签
        boolean result = RSACipher.checkSign(Config.CLIENT_PUBLIC_KEY, encryptText, signature);
        System.out.println("验签:\n" + result);
        //使用服务端私钥解密
        byte[] decryptText = RSACipher.decrypt(Config.SERVER_PRIVATE_KEY, encryptText);
        System.out.println("解密后:\n" + new String(decryptText));
    }
}
