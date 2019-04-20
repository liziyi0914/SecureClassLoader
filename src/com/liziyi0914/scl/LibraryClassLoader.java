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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;

/**
 *
 * @author liziyi0914
 */
public class LibraryClassLoader extends ClassLoader {

    URLClassLoader loader;
    
    public LibraryClassLoader(File fold) throws MalformedURLException{
        super();
        File[] files = fold.listFiles((dir, name) -> {
            return name.endsWith(".jar");
        });
        ArrayList<URL> li = new ArrayList<>();
        for (File file : files) {
            li.add(file.toURI().toURL());
        }
        URL[] tmp = new URL[li.size()];
        loader=new URLClassLoader(li.toArray(tmp));
    }
    
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        return loader.loadClass(name);
    }
    
}
