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
package com.liziyi0914.scl;

import com.liziyi0914.scl.jars.JARSFile;
import java.io.File;
import java.io.IOException;

/**
 *
 * @author liziyi0914
 */
public class SecureClassLoader extends ClassLoader {

    File jarsFile;
    JARSFile jars;
    LibraryClassLoader lcl;

    public SecureClassLoader(File f) throws Exception {
        this(JARSFile.load(f));
    }

    public SecureClassLoader(JARSFile f) throws IOException {
        super();
        this.jars = f;
        lcl = new LibraryClassLoader(new File(".\\lib"));
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        String filename = name + ".class";
        if (jars.exist(filename)) {
            byte[] data = jars.getFile(filename);
            return defineClass(name, data, 0, data.length);
        } else {
            System.err.println(name);
            return lcl.findClass(name);
        }
//        return null;
    }

}
