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

/**
 * A transformation consists of:
 * - A Cipher name
 * - A mode of operation
 * - A decision about (using or not using) padding 
 */
public enum Transformation {

    /*
    This enum has examples of available transformations (Cipher + Mode of Operation + Padding).
    ALL AVAILABLE Ciphers and modes and everything else:
    http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    */
    
    AES_CBC_NoPadding ("AES", "CBC", "NoPadding"),
    AES_CBC_PKCS5Padding ("AES", "CBC", "PKCS5Padding"),
    AES_ECB_NoPadding ("AES", "ECB", "NoPadding"),
    AES_ECB_PKCS5Padding ("AES", "ECB", "PKCS5Padding"),

    DES_CBC_NoPadding ("DES", "CBC", "NoPadding"),
    DES_CBC_PKCS5Padding ("DES", "CBC", "PKCS5Padding"),
    DES_ECB_NoPadding ("DES", "ECB", "NoPadding"),
    DES_ECB_PKCS5Padding ("DES", "ECB", "PKCS5Padding"),
    
    /*
     I researched and didnt find out exactly, but I believe the 3DES is called 'DESede' because it is equivalent to
     applying the DES E, DES D and DES E - where DES E is DES Encryption and DES D is DES Decryption.
    */
    DESede_CBC_NoPadding ("DESede", "CBC", "NoPadding"),
    DESede_CBC_PKCS5Padding ("DESede", "CBC", "PKCS5Padding"),
    DESede_ECB_NoPadding ("DESede", "ECB", "NoPadding"),
    DESede_ECB_PKCS5Padding ("DESede", "ECB", "PKCS5Padding"),

    RSA_ECB_PKCS1Padding ("RSA", "ECB", "PKCS1Padding"),
    RSA_ECB_OAEPWithSHA_1AndMGF1Padding ("RSA", "ECB", "OAEPWithSHA-1AndMGF1Padding"),
    RSA_ECB_OAEPWithSHA_256AndMGF1Padding ("RSA", "ECB", "OAEPWithSHA-256AndMGF1Padding");


    private final String cipher;
    private final String modeOfOperation;
    private final String padding;
    
    Transformation(String cipher, String modeOfOperation, String padding) {
        this.cipher = cipher;
        this.modeOfOperation = modeOfOperation;
        this.padding = padding;
    }
    
    public boolean requiresInitializationVector() {
        // http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
        // CBC requires an INITIALIZATION VECTOR
        return "CBC".equals(this.modeOfOperation);
    }

    public String asString() {
        return cipher + "/" + this.modeOfOperation + "/" + this.padding;
    }
    
    public String cipherName() {
        return this.cipher;
    }
    
}