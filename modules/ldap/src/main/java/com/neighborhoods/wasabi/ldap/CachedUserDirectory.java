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

import java.util.stream.Stream;

import com.google.inject.ImplementedBy;
import com.intuit.wasabi.userdirectory.UserDirectory;
import com.neighborhoods.wasabi.ldap.impl.DirectoryUser;
import com.neighborhoods.wasabi.ldap.impl.LdapUserDirectory;

/**
 * The Interface CachedUserDirectory.
 * 
 * This interface extends UserDirectory to establish a contract for caching of user retrievals from directory services.
 * It also collapses Authentication/Authorization calls for use with a delegate pattern.
 */
@ImplementedBy(LdapUserDirectory.class)
public interface CachedUserDirectory extends UserDirectory {

    /**
     * Add user to local cache
     * 
     * @param user The directory user to add to the cache
     * @return The result of the cache put operation
     */
    public DirectoryUser addUserToCache(DirectoryUser user);

    /**
     * Remove a user from the cache
     * 
     * @param The username of the user to remove
     * @return The result of the remove action
     */
    public DirectoryUser removeUserFromCache(String username);

    /**
     * Authenticate (e.g. during initial login) a given user
     * 
     * @param username - The username to authenticate
     * @param password - The password to authenticate
     * @return The directory user if successful
     */
    public DirectoryUser authenticate(String username, String password);

    /**
     * Get a stream of all users
     * 
     * @return All directory users
     */
    public Stream<DirectoryUser> getAllUsers();

    /**
     * Validate a directory token
     * 
     * @param username The username to validate
     * @param encryptedPassword The password to validate
     * @return true, if a directory token is valid
     */
    public boolean isDirectoryTokenValid(String username, String token);

    /**
     * Find a user by username
     * 
     * @param username The target user's username
     * @return The user object
     */
    public DirectoryUser lookupDirectoryUser(String username);

    /**
     * Refresh the cache.
     */
    public void refreshCache();
}
