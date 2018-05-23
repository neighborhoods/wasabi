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
package com.neighborhoods.wasabi.ldap;

import com.google.inject.ImplementedBy;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.neighborhoods.wasabi.ldap.impl.DirectoryUser;
import com.neighborhoods.wasabi.ldap.impl.LdapDelegate;

/**
 * The Interface DirectoryDelegate.
 * 
 * This delegate is responsible for performing all retrieval/authentication operations for a CachedUserDirectory
 * implementor.
 */
@ImplementedBy(LdapDelegate.class)
public interface DirectoryDelegate {

    /**
     * Attempt to authenticate the user based on the given user credentials.
     * 
     * @param userDirectory - The calling user directory
     * @param username - The target user
     * @param password - The target user password
     * @return directory user object
     * @throws AuthenticationException For all failures (e.g. user entered incorrect password or even when unable to
     *             connect to the directory service)
     */
    public DirectoryUser authenticate(CachedUserDirectory userDirectory, String username, String password)
            throws AuthenticationException;

    /**
     * Retrieve the user details from the directory service for a given email.
     * 
     * @param userDirectory the calling userDirectory
     * @param email The target user email
     * @throws AuthenticationException For all failures (e.g. unable to connect to the directory service)
     */
    public DirectoryUser getDirectoryUserByEmail(CachedUserDirectory userDirectory, String email)
            throws AuthenticationException;

    /**
     * Retrieve the user details from the directory service for a given username.
     * 
     * @param userDirectory the calling userDirectory
     * @param username The target user's username
     * @throws AuthenticationException For all failures (e.g. unable to connect to the directory service)
     */
    public DirectoryUser getDirectoryUserByUsername(CachedUserDirectory userDirectory, String username)
            throws AuthenticationException;

    /**
     * Validate a directory token
     * 
     * @param userDirectory - the calling user directory
     * @param username - The username to validate
     * @param encodedPassword - The encrypted password to validate
     * @return true, if directory token is valid
     */
    public boolean isDirectoryTokenValid(CachedUserDirectory userDirectory, String username, String encryptedPassword);

    /**
     * Populates the user cache with all Wasabi users
     * 
     * @param The calling CachedUserDirectory instance
     * @throws AuthenticationException For all failures (e.g. unable to connect to the directory service)
     */
    public void populateUserCache(CachedUserDirectory userDirectory) throws AuthenticationException;
}
