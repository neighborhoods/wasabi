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
package com.nhds.wasabi.ldap;

import com.google.inject.ImplementedBy;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.nhds.wasabi.ldap.CachedUserDirectory;
import com.nhds.wasabi.ldap.impl.DirectoryUser;
import com.nhds.wasabi.ldap.impl.LdapDelegate;

@ImplementedBy (LdapDelegate.class)
public interface DirectoryDelegate {
    public void populateUserCache(CachedUserDirectory userDirectory) throws AuthenticationException;

    public DirectoryUser getDirectoryUserByEmail(CachedUserDirectory userDirectory, String email) throws AuthenticationException;

    public DirectoryUser getDirectoryUserByUsername(CachedUserDirectory userDirectory, String username)
            throws AuthenticationException;

    public DirectoryUser authenticate(CachedUserDirectory userDirectory, String username, String password)
            throws AuthenticationException;

    public boolean isDirectoryTokenValid(CachedUserDirectory userDirectory, String username, String encryptedPassword);
}
