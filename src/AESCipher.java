import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * @author Taoyimin
 * @create 2019 05 07 12:31
 */
public class AESCipher {

    /**
     * 加密方法，使用key充当向量iv，增加加密算法的强度
     *
     * @param key 密钥
     * @param raw 需要加密的内容
     * @return
     */
    public static String encrypt(byte[] key, String raw) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] enCodeFormat = secretKey.getEncoded();
        SecretKeySpec seckey = new SecretKeySpec(enCodeFormat, "AES");
        Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(key);
        cipher.init(Cipher.ENCRYPT_MODE, seckey, iv);
        byte[] result = cipher.doFinal(raw.getBytes());
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(result);
    }

    /**
     * 解密方法，使用key充当向量iv，增加加密算法的强度
     *
     * @param key 密钥
     * @param enc 待解密内容
     * @return
     */
    public static String decrypt(byte[] key, String enc) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] enCodeFormat = secretKey.getEncoded();
        SecretKeySpec seckey = new SecretKeySpec(enCodeFormat, "AES");
        Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(key);
        cipher.init(Cipher.DECRYPT_MODE, seckey, iv);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] result = cipher.doFinal(decoder.decode(enc));
        return new String(result);
    }

    public static void main(String[] args) throws Exception {
        //客户端代码
        String text = "hello";
        //随机生成16位aes密钥
        byte[] aesKey = SecureRandomUtil.getRandom(16).getBytes();
        String encryptText = AESCipher.encrypt(aesKey, text);
        System.out.println("加密后:\n" + encryptText);
        String decryptText = AESCipher.decrypt(aesKey, encryptText);
        System.out.println("解密后:\n" + decryptText);
    }
}
