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

import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.userdirectory.UserDirectory;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

public class LdapUserDirectory implements UserDirectory {
    private static final long ONE_MINUTE_IN_MILLIS = 60000;
    private static final int CACHE_EXPIRY_PERIOD_MINUTES = 90;
    private HashMap<String, LdapUser> users;
    private LdapDelegateInterface ldap;

    /**
     * @param users a list of user credentials
     */
    public LdapUserDirectory() {
        this.ldap = LdapRequestDelegate.getInstance();
        refreshCache();
    }

    public void addUserToCache(LdapUser user) {
        this.users.put(user.getUsername().getUsername(), user);
    }

    /**
     * @param userEmail a user email address to check if it exists
     * @return a userinfo contain the user with that email address
     * @see UserDirectory#lookupUserByEmail(java.lang.String)
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {
        // TODO: convert to stream
        Iterator<Entry<String, LdapUser>> iterator = this.users.entrySet().iterator();
        while (iterator.hasNext()) {
            Entry<String, LdapUser> item = iterator.next();
            LdapUser cachedUser = item.getValue();
            if (userEmail.equals(cachedUser.getEmail())) {
                cachedUser = validateCachedUser(cachedUser);
                if (cachedUser != null) {
                    return cachedUser.getUserInfo();
                }
            }
        }
        LdapUser result = this.ldap.getLdapUserByEmail(this, userEmail);
        if (result != null) {
            return result.getUserInfo();
        }
        return null;
    }

    public void removeUserFromCache(String username) {
        this.users.remove(username);
    }

    @Override
    public UserInfo lookupUser(final Username username) {
        LdapUser result = getLdapUserFromCache(username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        result = this.ldap.getLdapUserByUsername(this, username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        return null;
    }

    protected LdapUser validateCachedUser(LdapUser cachedUser) {
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

    protected LdapUser getLdapUserFromCache(String username) {
        LdapUser cachedUser = this.users.get(username);
        if (cachedUser != null) {
            return validateCachedUser(cachedUser);
        }
        return null;
    }

    public LdapUser lookupLdapUser(final Username username) {
        LdapUser result = getLdapUserFromCache(username.getUsername());
        if (result != null) {
            return result;
        }
        return this.ldap.getLdapUserByUsername(this, username.getUsername());
    }

    public Stream<LdapUser> getAllUsers() {
        return mapToStream(this.users);
    }

    // Generic function to convert Map<K,V> to a Stream<V>
    private static <K, V> Stream<V> mapToStream(Map<K, V> map) {
        return map.values().stream();
    }

    public void refreshCache() {
        this.users = new HashMap<String, LdapUser>();
        ldap.populateUserCache(this);
    }

    public boolean isLdapTokenValid(String username, String encryptedPassword) {
        return ldap.isLdapTokenValid(this, username, encryptedPassword);
    }

    public LdapUser authenticate(String username, String password) {
        return ldap.authenticate(this, username, password);
    }
}
