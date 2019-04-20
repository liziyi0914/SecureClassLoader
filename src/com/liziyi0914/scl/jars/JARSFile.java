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
package com.liziyi0914.scl.jars;

import com.liziyi0914.pio.types.VarintType;
import com.liziyi0914.pio.types.StringType;
import com.liziyi0914.pio.types.FileType;
import com.liziyi0914.pio.types.BytesType;
import com.liziyi0914.scl.crypto.AES;
import com.liziyi0914.scl.crypto.RSA;
import com.liziyi0914.pio.PacketIn;
import com.liziyi0914.pio.PacketOut;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

/**
 *
 * @author liziyi0914
 */
public class JARSFile {
    
    HashMap<String, byte[]> resources = new HashMap<>();
    HashMap<String, String> mainifest = new HashMap<>();
    byte[] rsa_pub;
    byte[] key;
    byte[] key_crypted;
    static BytesType bytesType = new BytesType();
    static StringType strType = new StringType();
    static FileType fileType = new FileType();
    static VarintType varintType = new VarintType();
    
    HmacUtils hmac_sha1;
    HmacUtils hmac_sha256;

    private JARSFile() {
    }

    public static JARSFile newInstance() {
        return new JARSFile();
    }

    public byte[] Pack() throws IOException {
        PacketOut out = new PacketOut();
        
        out.write(varintType.out(new BigInteger(rsa_pub)));
        out.write(varintType.out(new BigInteger(key_crypted)));
        
        out.write(varintType.out(BigInteger.valueOf(mainifest.size())));
        for (Map.Entry<String, String> entry : mainifest.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            out.write(strType.out(key));
            out.write(strType.out(value));
        }
        
        out.write(varintType.out(BigInteger.valueOf(resources.size())));
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String key = entry.getKey();
            byte[] value = entry.getValue();
            out.write(fileType.out(key, value));
        }
        
        return out.finish();
    }

    static void log(String msg){
        System.out.println(msg);
    }
    
    public static JARSFile load(File f) throws Exception {
        JARSFile jars = newInstance();
        log("Loading "+f.getCanonicalPath());
        PacketIn in = new PacketIn(Files.readAllBytes(f.toPath()));
        
        log("loading Key");
        jars.rsa_pub = ((BigInteger)in.load(varintType.in())).toByteArray();
        jars.key_crypted = ((BigInteger)in.load(varintType.in())).toByteArray();
        jars.decryptKey();

        log("loading Mainifest");
        int count = ((BigInteger) in.load(varintType.in())).intValue();
        for (int i = 0; i < count; i++) {
            String key = (String) in.load(strType.in());
            String value = (String) in.load(strType.in());
            jars.mainifest.put(key, value);
        }

        log("loading Files");
        count = ((BigInteger) in.load(varintType.in())).intValue();
        FileType.SimpleFile file;
        for (int i = 0; i < count; i++) {
            file = (FileType.SimpleFile) in.load(fileType.in());
            jars.resources.put(file.getName(), file.getData());
        }
        
        return jars;
    }

    public void addFile(String fileName, byte[] data) throws IOException {
        try {
            resources.put(confuse(fileName), AES.encrypt(data, this.key));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | UnsupportedEncodingException | NoSuchPaddingException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(JARSFile.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public byte[] getFile(String fileName) {
        try {
            return AES.decrypt(resources.get(confuse(fileName)), this.key);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException ex) {
            Logger.getLogger(JARSFile.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new byte[0];
    }

    public void putAttribute(String key, String value) {
        try {
            mainifest.put(confuse(key), Base64.encodeBase64String(AES.encrypt(value.getBytes(),this.key)));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | UnsupportedEncodingException | NoSuchPaddingException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(JARSFile.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String getAttribute(String key) {
        try {
            return new String(AES.decrypt(Base64.decodeBase64(mainifest.get(confuse(key))), this.key));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException ex) {
            Logger.getLogger(JARSFile.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    public String getMainClass() {
        return getAttribute("Main-Class");
    }

    public String getLaunchClass() {
        return getAttribute("Launch-Class");
    }

    String confuse(String name) {
//        System.out.println(name + "\t\t" + (DigestUtils.sha1Hex(name) + DigestUtils.sha1Hex(DigestUtils.sha256Hex(name))));
        return hmac_sha1.hmacHex(name) + hmac_sha1.hmacHex(hmac_sha256.hmac(name));
    }

    public void forEach(BiConsumer<String, byte[]> action) {
        resources.forEach(action);
    }

    public boolean exist(String name) {
        return resources.containsKey(confuse(name));
    }

    public void initCrypto(byte[] key, byte[] rsa_pub, byte[] rsa_pri) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.key = key;
        this.rsa_pub = rsa_pub;
        this.key_crypted = RSA.EncryptKey(AES.getKey(key), RSA.loadPrivateKey(rsa_pri));
        initHMAC();
    }
    
    public void initCrypto(byte[] rsa_pub, byte[] rsa_pri) throws Exception {
        initCrypto(AES.genKey(), rsa_pub, rsa_pri);
    }
    
    public void decryptKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        this.key = RSA.DecryptKey(this.key_crypted, RSA.loadPublicKey(this.rsa_pub)).getEncoded();
        initHMAC();
    }
    
    public void initHMAC(){
        this.hmac_sha1 = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, this.key);
        this.hmac_sha256 = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, this.key);
    }
}
