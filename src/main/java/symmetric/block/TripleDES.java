package symmetric.block;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public class TripleDES {

    private static final String STRING_ENCODING = "UTF8";
    public static final String SECRET_KEY_ALGORITH = "DESede";

    private String transformation;
    private Cipher cipher;
    private SecretKey key;

    public TripleDES(String transformation, String key) throws Exception {
        this.transformation = transformation;
        this.cipher = Cipher.getInstance(transformation);
        this.key = genSecretKey(key);
    }

    private SecretKey genSecretKey(String key) throws Exception {
        return new SecretKeySpec(key.getBytes(STRING_ENCODING), SECRET_KEY_ALGORITH);
    }

    public byte[] encrypt(String plainText) throws Exception {
        initCipher(Cipher.ENCRYPT_MODE);
        byte[] plainTextBytes = plainText.getBytes(STRING_ENCODING);
        return cipher.doFinal(plainTextBytes);
    }

    private void initCipher(int opmode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (transformation.contains("CBC")) {
            cipher.init(opmode, key, new IvParameterSpec(new byte[8]));
        } else {
            cipher.init(opmode, key);
        }
    }

    public String decrypt(byte[] cypherText) throws Exception {
        initCipher(Cipher.DECRYPT_MODE);
        byte[] plainText = cipher.doFinal(cypherText);
        return new String(plainText);
    }

    private void encryptDecryptAndPrint(String plaintext) throws Exception {
        byte[] ciphertext = encrypt(plaintext);
        System.out.println(String.format("%45s -> PLAIN: %s     CIPHERTEXT: %-25s  %d", transformation, plaintext, Base64.encodeBase64String(ciphertext), ciphertext.length));
        if (!plaintext.equals(decrypt(ciphertext))) {
            System.out.println("OOPS!!! IT DID NOT DECRYPT RIGHT! Plaintext --> "+plaintext);
        }
    }

    /**
     * @param transformation The algorithm, block cipher mode of operation (CBC, EBC), and if there will be padding or not
     * @param k1 key of 8 bytes = 64 bits (I think each a bit for each byte is [sort of discarded and] used as parity) = 56 effective bits
     * @param k2 key of 8 bytes = 64 bits = 56 effective bits
     * @param k3 key of 8 bytes = 64 bits
     * @param input String to be encrypted/decrypted - as the block size is 64 bits, this string should have size multiple of 8 bytes (when encoded utf-8)
     */
    private static void transform(String transformation, String k1, String k2, String k3, String input) throws Exception {
        new TripleDES(transformation, k1 + k2 + k3).encryptDecryptAndPrint(input);
    }

    public static void main(String args[]) throws Exception {
        /*
        AES/CBC/NoPadding (128)
        AES/CBC/PKCS5Padding (128)
        AES/ECB/NoPadding (128)
        AES/ECB/PKCS5Padding (128)
        DES/CBC/NoPadding (56)
        DES/CBC/PKCS5Padding (56)
        DES/ECB/NoPadding (56)
        DES/ECB/PKCS5Padding (56)
        DESede/CBC/NoPadding (168)
        DESede/CBC/PKCS5Padding (168)
        DESede/ECB/NoPadding (168)
        DESede/ECB/PKCS5Padding (168)
        RSA/ECB/PKCS1Padding (1024, 2048)
        RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
        RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
         */
        transform("DESede/CBC/NoPadding",    "12345678", "55665544", "55665544", "12345678");
        transform("DESede/CBC/PKCS5Padding", "12345678", "55665544", "55665544", "12345678");
        transform("DESede/ECB/NoPadding",    "12345678", "55665544", "55665544", "12345678");
        transform("DESede/ECB/PKCS5Padding", "12345678", "55665544", "55665544", "12345678");
        
        System.out.println();
        System.out.println("SOME TESTS. FOR ALL BELOW THE CIPHERTEXT SHOULD BE THE SAME:");
        transform("DESede/CBC/NoPadding", "12345678", "55665544", "55665544", "myText64"); // only k1 should have effect
        transform("DESede/CBC/NoPadding", "12345678", "ADSSDJSD", "ADSSDJSD", "myText64"); // only k1 should have effect
        transform("DESede/CBC/NoPadding", "DSA6546K", "DSA6546K", "12345678", "myText64"); // only k3 should have effect
        transform("DESede/CBC/NoPadding", "98689789", "98689789", "12345678", "myText64"); // only k3 should have effect

        System.out.println();
        System.out.println("ECB and CBC should be equal on the first block. From the second on, they should differ, as CBC also XORs them.");
        transform("DESede/ECB/NoPadding", "11111111", "22222222", "33333333", "myText64");
        transform("DESede/CBC/NoPadding", "11111111", "22222222", "33333333", "myText64");
        transform("DESede/ECB/NoPadding", "11111111", "22222222", "33333333", "myText64myText64");
        transform("DESede/CBC/NoPadding", "11111111", "22222222", "33333333", "myText64myText64");
    }

}