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

package symmetric.block;

import cipher.Transformation;
import cipher.UsableCipher;

public class TripleDES {

    /**
     * @param transformation The algorithm, block cipher mode of operation (CBC, EBC), and if there will be padding or not
     * @param k1 key of 8 bytes = 64 bits (I think each a bit for each byte is [sort of discarded and] used as parity) = 56 effective bits
     * @param k2 key of 8 bytes = 64 bits = 56 effective bits
     * @param k3 key of 8 bytes = 64 bits
     * @param input String to be encrypted/decrypted - as the block size is 64 bits, this string should have size multiple of 8 bytes (when encoded utf-8)
     */
    private static void transform(Transformation transformation, String k1, String k2, String k3, String input) throws Exception {
        UsableCipher cipher = new UsableCipher(transformation, k1 + k2 + k3);
        cipher.encryptDecryptAndPrint(input);
    }

    public static void main(String args[]) throws Exception {

        transform(Transformation.DESede_CBC_NoPadding,    "12345678", "55665544", "55665544", "12345678");
        transform(Transformation.DESede_CBC_PKCS5Padding, "12345678", "55665544", "55665544", "12345678");
        transform(Transformation.DESede_ECB_NoPadding,    "12345678", "55665544", "55665544", "12345678");
        transform(Transformation.DESede_ECB_PKCS5Padding, "12345678", "55665544", "55665544", "12345678");
        
        System.out.println();
        System.out.println("SOME TESTS. FOR ALL BELOW THE CIPHERTEXT SHOULD BE THE SAME:");
        transform(Transformation.DESede_CBC_NoPadding, "12345678", "55665544", "55665544", "myText64"); // only k1 should have effect
        transform(Transformation.DESede_CBC_NoPadding, "12345678", "ADSSDJSD", "ADSSDJSD", "myText64"); // only k1 should have effect
        transform(Transformation.DESede_CBC_NoPadding, "DSA6546K", "DSA6546K", "12345678", "myText64"); // only k3 should have effect
        transform(Transformation.DESede_CBC_NoPadding, "98689789", "98689789", "12345678", "myText64"); // only k3 should have effect

        System.out.println();
        System.out.println("ECB and CBC should be equal on the first block (as the CBC initialization vector used is 00000000 - see initCipher())." +
                " From the second on, they should differ, as CBC will do XORing while EBC won't.");
        transform(Transformation.DESede_ECB_NoPadding, "11111111", "22222222", "33333333", "myText64");
        transform(Transformation.DESede_CBC_NoPadding, "11111111", "22222222", "33333333", "myText64");
        transform(Transformation.DESede_ECB_NoPadding, "11111111", "22222222", "33333333", "myText64myText64");
        transform(Transformation.DESede_CBC_NoPadding, "11111111", "22222222", "33333333", "myText64myText64");
    }

}