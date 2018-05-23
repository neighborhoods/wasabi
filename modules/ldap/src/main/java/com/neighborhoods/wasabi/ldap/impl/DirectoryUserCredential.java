/**
 * Wasabi-LDAP Copyright 2018 Neighborhoods.com
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.neighborhoods.wasabi.ldap.impl;

import org.apache.commons.codec.binary.Base64;

/**
 * The class DirectoryUserCredential.
 * 
 * Simple user credentials pojo. Necessary due to protected package restrictions in base UserCredential class.
 */
public class DirectoryUserCredential {

    /** The username. */
    protected final String username;

    /** The password. */
    protected final String password;

    /**
     * Instantiates a new directory user credential.
     *
     * @param username the username
     * @param password the password
     */
    public DirectoryUserCredential(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Convert this object to a base 64 encoded string.
     *
     * @return the string
     */
    public String toBase64Encode() {
        return new String(Base64.encodeBase64((this.username + ":" + this.password).getBytes()));
    }
}
