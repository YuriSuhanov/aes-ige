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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES IGE cipher implementation.
 * <p/>
 * IGE (Infinite Garble Extension) is a block cipher mode.
 * It has a property that errors are propagated forward indefinitely.
 * <p/>
 * Compatible with OpenSSL.
 * <p/>
 * Algorithm description:
 * http://www.links.org/files/openssl-ige.pdf
 * <p/>
 * Author: Yuri V. Suhanov (Yuri.Suhanov@gmail.com)
 * Created: 23.12.2013
 */
public final class AESIGECipher {

    private static final String AES_ALGORITHM = "AES";
    private static final String ECB_MODE = "ECB";
    private static final String NO_PADDING = "NoPadding";

    private static final String AES_CIPHER_TRANSFORMATION =
            String.format("%s/%s/%s", AES_ALGORITHM, ECB_MODE, NO_PADDING);

    private final Cipher mEmbeddedCipher;
    private final SecretKey mSecretKey;

    private final int mBlockSize;

    private byte[] mIVRaw;

    public AESIGECipher(byte[] secretKeyRaw, byte[] ivRaw) {
        try {
            checkSecretKey(secretKeyRaw);
            mSecretKey = new SecretKeySpec(secretKeyRaw, AES_ALGORITHM);

            mEmbeddedCipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
            mBlockSize = mEmbeddedCipher.getBlockSize();

            checkIV(ivRaw);
            mIVRaw = ivRaw.clone();
        } catch (Exception exception) {
            exception.printStackTrace();
            throw new RuntimeException(exception.getMessage());
        }
    }

    public byte[] getIV() {
        return mIVRaw.clone();
    }

    public void setIV(byte[] ivRaw) {
        checkIV(ivRaw);
        mIVRaw = ivRaw.clone();
    }

    public byte[] encrypt(byte[] plainBytes) {
        return process(plainBytes, true);
    }

    public byte[] decrypt(byte[] cipherBytes) {
        return process(cipherBytes, false);
    }

    private byte[] process(byte[] inputBytes, boolean encrypt) {
        checkInputByteArray(inputBytes);

        int blocksCount = inputBytes.length / mBlockSize;
        byte[] outputBytes = createBlocks(blocksCount);

        initCipher(encrypt);

        byte[] iv1 = extractBlock(mIVRaw, encrypt ? 0 : 1);
        byte[] iv2 = extractBlock(mIVRaw, encrypt ? 1 : 0);

        byte[] inputBlock;
        byte[] outputBlock = createBlock();

        for (int i = 0; i < blocksCount; i++) {
            inputBlock = extractBlock(inputBytes, i);

            xorBlocks(inputBlock, iv1, outputBlock);
            outputBlock = applyCipher(outputBlock);
            xorBlocks(outputBlock, iv2, outputBlock);

            copyBlock(outputBlock, outputBytes, i);

            iv1 = outputBlock;
            iv2 = inputBlock;
        }

        return outputBytes;
    }

    /*
     * Methods to interact with embedded cipher
     */

    private void initCipher(boolean encrypt) {
        try {
            mEmbeddedCipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, mSecretKey);
        } catch (Exception exception) {
            exception.printStackTrace();
            throw new RuntimeException(exception.getMessage());
        }
    }

    private byte[] applyCipher(byte[] block) {
        try {
            return mEmbeddedCipher.doFinal(block);
        } catch (Exception exception) {
            exception.printStackTrace();
            throw new RuntimeException(exception.getMessage());
        }
    }

    /*
     * Methods to manipulate with blocks
     */

    private byte[] extractBlock(byte[] bytes, int blockPosition) {
        byte[] blockBytes = new byte[mBlockSize];
        System.arraycopy(bytes, mBlockSize * blockPosition, blockBytes, 0, mBlockSize);
        return blockBytes;
    }

    private void copyBlock(byte[] block, byte[] resultBytes, int blockPosition) {
        System.arraycopy(block, 0, resultBytes, mBlockSize * blockPosition, mBlockSize);
    }

    private byte[] createBlock() {
        return createBlocks(1);
    }

    private byte[] createBlocks(int blocksCount) {
        return new byte[mBlockSize * blocksCount];
    }

    private void xorBlocks(byte[] block1, byte[] block2, byte[] resultBlock) {
        for (int i = 0; i < mBlockSize; i++) {
            resultBlock[i] = (byte) (block1[i] ^ block2[i]);
        }
    }

    /*
     * Validation methods
     */

    private void checkSecretKey(byte[] secretKeyRaw) {
        if (secretKeyRaw == null) {
            throw new NullPointerException("Secret key byte array can't be null!");
        }
        int length = secretKeyRaw.length;
        if (length != 16 && length != 24 && length != 32) {
            throw new IllegalArgumentException("Secret key length must be 128, 192 or 256 bit!");
        }
    }

    private void checkIV(byte[] ivRaw) {
        if (ivRaw == null) {
            throw new NullPointerException("Initialization vector byte array can't be null!");
        }
        int validLength = mBlockSize * 2;
        if (ivRaw.length != validLength) {
            throw new IllegalArgumentException("IV length must be " + validLength + " bytes!");
        }
    }

    private void checkInputByteArray(byte[] byteArray) {
        if (byteArray == null) {
            throw new NullPointerException("Input byte array can't be null!");
        }
        if (byteArray.length % mBlockSize != 0) {
            throw new IllegalArgumentException("Input byte array length must be a multiple of the block size!");
        }
    }

}