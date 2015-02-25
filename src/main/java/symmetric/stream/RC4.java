package symmetric.stream;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public class RC4 {

    private static final String ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"

    public static void main(String[] args) throws Exception {
        String plaintext = "Howdy!";

        KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        Cipher rc4 = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        byte[] ciphertextBytes = encrypt(plaintext, secretKey, rc4);

        decrypt(secretKey, rc4, ciphertextBytes);
    }

    private static byte[] encrypt(String plaintext, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        System.out.println("RC4 ciphertext base64 encoded: " + Base64.encodeBase64String(ciphertextBytes));
        return ciphertextBytes;
    }

    private static void decrypt(SecretKey secretKey, Cipher rc4, byte[] ciphertextBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.DECRYPT_MODE, secretKey, rc4.getParameters());
        byte[] byteDecryptedText = rc4.doFinal(ciphertextBytes);
        String plaintextBack = new String(byteDecryptedText);
        System.out.println("Decrypted back to: " + plaintextBack);
    }

}