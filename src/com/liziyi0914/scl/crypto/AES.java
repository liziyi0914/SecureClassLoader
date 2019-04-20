/*
 * Copyright (C) 2019 liziyi0914.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/lgpl.txt>
 */
package com.liziyi0914.scl.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author liziyi0914
 */
public class AES {

    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";//默认的加密算法

    /**
     * AES 加密操作
     *
     * @param content 待加密内容
     * @param password 加密密码
     * @return 返回加密数据
     */
    public static byte[] encrypt(byte[] data, String password) throws NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {
        return encrypt(data, genKey(password));
    }

    /**
     * AES 加密操作
     *
     * @param content 待加密内容
     * @param password 加密密码
     * @return 返回加密数据
     */
    public static byte[] encrypt(byte[] data, byte[] password) throws NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);// 创建密码器
        cipher.init(Cipher.ENCRYPT_MODE, getKey(password));// 初始化为加密模式的密码器
        byte[] result = cipher.doFinal(data);// 加密
        return result;
    }

    /**
     * AES 解密操作
     *
     * @param content
     * @param password
     * @return
     */
    public static byte[] decrypt(byte[] data, byte[] password) throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException {
        //实例化
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
        //使用密钥初始化，设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, getKey(password));
        //执行操作
        byte[] result = cipher.doFinal(data);
        return result;
    }

    /**
     * AES 解密操作
     *
     * @param content
     * @param password
     * @return
     */
    public static byte[] decrypt(byte[] data, String password) throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException {
        return decrypt(data, genKey(password));
    }

    /**
     * 生成加密秘钥
     *
     * @return
     */
    public static byte[] genKey(final byte[] seed) throws NoSuchAlgorithmException {
        //返回生成指定算法密钥生成器的 KeyGenerator 对象
        KeyGenerator kg = null;
        kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        //AES 要求密钥长度为 128
        kg.init(128, new SecureRandom(seed));
        //生成一个密钥
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 生成加密秘钥
     *
     * @return
     */
    public static byte[] genKey() throws NoSuchAlgorithmException {
        return genKey(new SecureRandom().generateSeed(16));
    }

    /**
     * 生成加密秘钥
     *
     * @return
     */
    public static byte[] genKey(final String seed) throws NoSuchAlgorithmException {
        return genKey(seed.getBytes());
    }

    /**
     * 生成加密秘钥
     *
     * @return
     */
    public static SecretKeySpec getKey(byte[] key) throws NoSuchAlgorithmException {
        return new SecretKeySpec(key, KEY_ALGORITHM);// 转换为AES专用密钥
    }
}
