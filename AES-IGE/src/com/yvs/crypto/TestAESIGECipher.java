/*
 * Copyright 2013 Yuri V. Suhanov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yvs.crypto;

import java.util.Arrays;

/**
 * Test class for AES IGE cipher implementation.
 * <p/>
 * Author: Yuri V. Suhanov (Yuri.Suhanov@gmail.com)
 * Created: 23.12.2013
 */
public final class TestAESIGECipher {

    public static void main(String[] args) {
        test1();
        test2();
    }

    private static void test1() {
        System.out.println("***** BEGIN TEST 1 *****\n");

        final byte[] secretKey = hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
        final byte[] iv = hexStringToByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        final byte[] plainBytes = hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
        final byte[] expectedCipherBytes = hexStringToByteArray("1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB");

        AESIGECipher cipher = new AESIGECipher(secretKey, iv);
        byte[] cipherBytes = cipher.encrypt(plainBytes);

        System.out.println("Plain bytes:\n" + toString(plainBytes));
        System.out.println("Expected cipher bytes:\n" + toString(expectedCipherBytes));
        System.out.println("Actual cipher bytes:\n" + toString(cipherBytes));

        byte[] corruptedCipherBytes = cipherBytes.clone();
        corruptedCipherBytes[1] = (byte) (0xCC);

        byte[] decryptedCipherBytes = cipher.decrypt(cipherBytes);
        byte[] decryptedCorruptedCipherBytes = cipher.decrypt(corruptedCipherBytes);

        System.out.println("Decrypted cipher bytes:\n" + toString(decryptedCipherBytes));
        System.out.println("Decrypted corrupted cipher bytes:\n" + toString(decryptedCorruptedCipherBytes));

        System.out.println(Arrays.equals(expectedCipherBytes, cipherBytes)
                ? "Encryption test passed!" : "Encryption test failed!");
        System.out.println(Arrays.equals(decryptedCipherBytes, plainBytes)
                ? "Decryption test passed!" : "Decryption test failed!");

        System.out.println("\n***** END TEST 1 *****\n");
    }

    private static void test2() {
        System.out.println("***** BEGIN TEST 2 *****\n");

        final byte[] secretKey = hexStringToByteArray("5468697320697320616E20696D706C65");
        final byte[] iv = hexStringToByteArray("6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353");
        final byte[] plainBytes = hexStringToByteArray("99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B");
        final byte[] expectedCipherBytes = hexStringToByteArray("4C2E204C6574277320686F70652042656E20676F74206974207269676874210A");

        AESIGECipher cipher = new AESIGECipher(secretKey, iv);
        byte[] cipherBytes = cipher.encrypt(plainBytes);

        System.out.println("Plain bytes:\n" + toString(plainBytes));
        System.out.println("Expected cipher bytes:\n" + toString(expectedCipherBytes));
        System.out.println("Actual cipher bytes:\n" + toString(cipherBytes));

        byte[] corruptedCipherBytes = cipherBytes.clone();
        corruptedCipherBytes[1] = (byte) (0xCC);

        byte[] decryptedCipherBytes = cipher.decrypt(cipherBytes);
        byte[] decryptedCorruptedCipherBytes = cipher.decrypt(corruptedCipherBytes);

        System.out.println("Decrypted cipher bytes:\n" + toString(decryptedCipherBytes));
        System.out.println("Decrypted corrupted cipher bytes:\n" + toString(decryptedCorruptedCipherBytes));

        System.out.println(Arrays.equals(expectedCipherBytes, cipherBytes)
                ? "Encryption test passed!" : "Encryption test failed!");
        System.out.println(Arrays.equals(decryptedCipherBytes, plainBytes)
                ? "Decryption test passed!" : "Decryption test failed!");

        System.out.println("\n***** END TEST 2 *****\n");
    }

    /*
     * Helper methods
     */

    public static byte[] hexStringToByteArray(String string) {
        int length = string.length();
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
                    + Character.digit(string.charAt(i + 1), 16));
        }
        return byteArray;
    }

    public static String toPaddedHexString(int number) {
        return String.format("%4s", Integer.toHexString(number).toUpperCase()).replace(' ', '0');
    }

    public static String toPaddedHexString(byte number) {
        return String.format("%2s", Integer.toHexString(((int) number) & 0xFF).toUpperCase()).replace(' ', '0');
    }

    public static String toString(byte[] byteArray) {
        if (null == byteArray) return "null";

        final int bytesPerLine = 16;
        final String lineBytesCountSeparator = " | ";
        final String bytesSeparator = " ";
        final String lineSeparator = System.getProperty("line.separator");

        final StringBuilder stringBuilder = new StringBuilder();

        int bytesCount = byteArray.length;

        int lastLineBytes = bytesCount % bytesPerLine;
        if (lastLineBytes == 0) lastLineBytes = bytesPerLine;
        int lines = bytesCount / bytesPerLine + (lastLineBytes == bytesPerLine ? 0 : 1);

        for (int i = 0; i < lines; i++) {
            stringBuilder.append(toPaddedHexString(bytesPerLine * i))
                    .append(lineBytesCountSeparator);
            int bytesInLine = (i == lines - 1) ? lastLineBytes : bytesPerLine;

            for (int j = 0; j < bytesInLine; j++) {
                stringBuilder.append(toPaddedHexString(byteArray[i * bytesPerLine + j]))
                        .append(bytesSeparator);
            }
            stringBuilder.append(lineSeparator);
        }

        return stringBuilder.toString();
    }

}
