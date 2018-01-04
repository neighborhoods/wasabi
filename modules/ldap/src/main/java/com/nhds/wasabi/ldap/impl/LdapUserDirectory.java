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
package com.nhds.wasabi.ldap.impl;

import com.google.inject.Singleton;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.userdirectory.UserDirectory;
import com.nhds.wasabi.ldap.CachedUserDirectory;
import com.nhds.wasabi.ldap.DirectoryDelegate;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

@Singleton
public class LdapUserDirectory implements CachedUserDirectory {
    private static final long ONE_MINUTE_IN_MILLIS = 60000;
    private static final int CACHE_EXPIRY_PERIOD_MINUTES = 90;
    private ConcurrentHashMap<String, DirectoryUser> users;
    private DirectoryDelegate ldap;

    /**
     * @param users a list of user credentials
     */
    public LdapUserDirectory() {
        this.ldap = LdapDelegate.getInstance();
        refreshCache();
    }

    public DirectoryUser addUserToCache(DirectoryUser user) {
        return this.users.put(user.getUsername().getUsername(), user);
    }

    /**
     * @param userEmail a user email address to check if it exists
     * @return a userinfo contain the user with that email address
     * @see UserDirectory#lookupUserByEmail(java.lang.String)
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {
        // TODO: convert to stream
        Iterator<Entry<String, DirectoryUser>> iterator = this.users.entrySet().iterator();
        while (iterator.hasNext()) {
            Entry<String, DirectoryUser> item = iterator.next();
            DirectoryUser cachedUser = item.getValue();
            if (userEmail.equals(cachedUser.getEmail())) {
                cachedUser = validateCachedUser(cachedUser);
                if (cachedUser != null) {
                    return cachedUser.getUserInfo();
                }
            }
        }
        DirectoryUser result = this.ldap.getDirectoryUserByEmail(this, userEmail);
        if (result != null) {
            return result.getUserInfo();
        }

        return null;
    }

    public DirectoryUser removeUserFromCache(String username) {
        return this.users.remove(username);
    }

    @Override
    public UserInfo lookupUser(final Username username) {
        DirectoryUser result = getDirectoryUserFromCache(username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        result = this.ldap.getDirectoryUserByUsername(this, username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        return null;
    }

    protected DirectoryUser validateCachedUser(DirectoryUser cachedUser) {
        if (cachedUser != null) {
            Date expirationDate = new Date(
                    cachedUser.getCacheTimestamp() + (CACHE_EXPIRY_PERIOD_MINUTES * ONE_MINUTE_IN_MILLIS));
            Date now = new Date();
            if (now.after(expirationDate)) {
                removeUserFromCache(cachedUser.getUsername().getUsername());
                cachedUser = null;
            }
        }
        return cachedUser;
    }

    protected DirectoryUser getDirectoryUserFromCache(String username) {
        DirectoryUser cachedUser;
        cachedUser = this.users.get(username);

        if (cachedUser != null) {
            return validateCachedUser(cachedUser);
        }
        return null;
    }

    public DirectoryUser lookupDirectoryUser(String username) {
        DirectoryUser result = getDirectoryUserFromCache(username);
        if (result != null) {
            return result;
        }
        return this.ldap.getDirectoryUserByUsername(this, username);
    }

    public Stream<DirectoryUser> getAllUsers() {
        Stream<DirectoryUser> result = null;
        result = mapToStream(this.users);
        return result;
    }

    // Generic function to convert Map<K,V> to a Stream<V>
    private static <K, V> Stream<V> mapToStream(Map<K, V> map) {
        return map.values().stream();
    }

    public void refreshCache() {
        if (this.users == null) {
            this.users = new ConcurrentHashMap<String, DirectoryUser>();
        } else {
            this.users.clear();
        }
        ldap.populateUserCache(this);
    }

    public boolean isDirectoryTokenValid(String username, String encryptedPassword) {
        return ldap.isDirectoryTokenValid(this, username, encryptedPassword);
    }

    public DirectoryUser authenticate(String username, String password) {
        return ldap.authenticate(this, username, password);
    }
}
