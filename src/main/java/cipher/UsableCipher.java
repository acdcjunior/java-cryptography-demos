/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 acdcjunior
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package cipher;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public class UsableCipher {

    private static final String STRING_ENCODING = "UTF8";
    
    protected Transformation transformation;
    protected Cipher cipher;
    protected SecretKey key;

    public UsableCipher(Transformation transformation, String key) throws Exception {
        this.cipher = Cipher.getInstance(transformation.asString());
        this.transformation = transformation;
        this.key = generateSecretKey(key, transformation.cipherName());
    }

    protected SecretKey generateSecretKey(String key, String secretKeyAlgorithm) throws Exception {
        return new SecretKeySpec(bytes(key), secretKeyAlgorithm);
    }

    private byte[] bytes(String key) throws UnsupportedEncodingException {
        return key.getBytes(STRING_ENCODING);
    }

    public byte[] encrypt(String plainText) throws Exception {
        initCipher(Cipher.ENCRYPT_MODE);
        byte[] plainTextBytes = bytes(plainText);
        return cipher.doFinal(plainTextBytes);
    }

    private void initCipher(int opmode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (transformation.requiresInitializationVector()) {
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

    public void encryptDecryptAndPrint(String plaintext) throws Exception {
        byte[] ciphertext = encrypt(plaintext);
        System.out.println(String.format("%45s -> PLAIN: %s     CIPHERTEXT: %-25s  %d", transformation, plaintext, Base64.encodeBase64String(ciphertext), ciphertext.length));
        if (!plaintext.equals(decrypt(ciphertext))) {
            System.out.println("OOPS!!! IT DID NOT DECRYPT RIGHT! Plaintext --> "+plaintext);
        }
    }
    
}