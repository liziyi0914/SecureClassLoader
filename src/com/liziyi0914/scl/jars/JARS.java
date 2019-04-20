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

import com.liziyi0914.scl.crypto.AES;
import com.liziyi0914.scl.crypto.RSA;
import java.io.File;
import java.io.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author liziyi0914
 */
public class JARS {

    public static JARSFile pack(File file,byte[] key, byte[] rsa_pub, byte[] rsa_pri) throws Exception {
        JARSFile result = JARSFile.newInstance();
        result.initCrypto(key, rsa_pub, rsa_pri);
        JarInputStream in = new JarInputStream(new FileInputStream(file));
        JarEntry entry;
        in.getManifest().getMainAttributes().forEach(((k, v) -> {
            result.putAttribute((String) k.toString(), (String) v);
        }));
        while ((entry = in.getNextJarEntry()) != null) {
            if (entry.isDirectory()) {
                continue;
            }
            String name = entry.getName().replaceAll("/", ".");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int buffer;
            while ((buffer = in.read()) != -1) {
                out.write(buffer);
            }
            result.addFile(name, out.toByteArray());
        }
        return result;
    }
    
    public static JARSFile pack(File file,HashMap<String, String> cfg, KeyPair pair) throws Exception {
        JARSFile out = null;
        if (file.exists()) {
            out = pack(file, AES.genKey(), RSA.getPublicKey(pair).getEncoded(), RSA.getPrivateKey(pair).getEncoded());
            for (Map.Entry<String, String> entry : cfg.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                out.putAttribute(key, value);
            }
        } else {
            throw new FileNotFoundException();
        }
        return out;
    }

    public static void unpack(File jarsFile, File root) throws IOException, Exception {
        JARSFile jars = JARSFile.load(jarsFile);
        jars.forEach((name, data) -> {
            File f = new File(root, name);
            try {
                f.createNewFile();
                FileOutputStream out = new FileOutputStream(f);
                out.write(data);
                out.flush();
                out.close();
            } catch (IOException ex) {
                Logger.getLogger(JARS.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
    }

}
