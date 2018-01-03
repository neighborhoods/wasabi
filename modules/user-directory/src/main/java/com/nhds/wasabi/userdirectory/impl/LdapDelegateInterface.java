/**
 * Copyright 2018 Neighborhoods.com
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
package com.nhds.wasabi.userdirectory.impl;

import com.intuit.wasabi.exceptions.AuthenticationException;

public interface LdapDelegateInterface {
    public void populateUserCache(LdapUserDirectory userDirectory) throws AuthenticationException;

    public LdapUser getLdapUserByEmail(LdapUserDirectory userDirectory, String email) throws AuthenticationException;

    public LdapUser getLdapUserByUsername(LdapUserDirectory userDirectory, String username)
            throws AuthenticationException;

    public LdapUser authenticate(LdapUserDirectory ldapUserDirectory, String username, String password)
            throws AuthenticationException;

    public boolean isLdapTokenValid(LdapUserDirectory ldapUserDirectory, String username, String encryptedPassword);
}
