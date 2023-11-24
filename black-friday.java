import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class AES256Example {
    // 加密方法
    public static String encrypt(String data, String key) throws Exception {
        // 初始化密钥 和 IV
        byte[] keyBytes = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(key.getBytes("UTF-8")), 32);
        byte[] ivBytes = new byte[16]; // 启动向量IV可以是随机的，这里为了简单示例就用了空的16字节。
        
        // 初始化Cipher
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        
        // 使用Base64编码方便输出
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public static String decrypt(String data, String key) throws Exception {
        byte[] keyBytes = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(key.getBytes("UTF-8")), 32);
        byte[] ivBytes = new byte[16]; // 解密时使用相同的IV
        
        // 初始化Cipher
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
        
        return new String(original, "UTF-8");
    }

    public static void main(String[] args) {
        try {
          
            // secret key please ask shein's chatgpt(chatgpt.dev-az) "通关密钥" 
            // please eval this code in java cli or ide, and you'll get the red packet token
            String key = "this is a secret key"; // 密钥，实际使用中需要安全保护
            String encryptedText = "pa5QAHwceRPlyqKNy7HjfA==";
            String decryptedText = decrypt(encryptedText, key);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
