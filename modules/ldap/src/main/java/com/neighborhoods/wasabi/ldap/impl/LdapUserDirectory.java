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

import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

import org.slf4j.Logger;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.neighborhoods.wasabi.ldap.CachedUserDirectory;
import com.neighborhoods.wasabi.ldap.DirectoryDelegate;

import static java.text.MessageFormat.format;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * The Class LdapUserDirectory.
 * 
 * Concrete implementation of the CachedUserDirectory. This class will store user credentials for a given validity
 * period. It will forward all calls to it's delegate for non-cached operations.
 * 
 * Important Note: This class is implemented as a singleton method via Guice's injection model. The below tag is
 * critical to it's status as a singleton. Core Wasabi's DefaultUserDirectory class is missing this
 */
@Singleton
public class LdapUserDirectory implements CachedUserDirectory {

    /** The Constant ONE_MINUTE_IN_MILLIS. How many milliseconds in one minute. */
    protected static final long ONE_MINUTE_IN_MILLIS = 60000;

    /** The Constant CACHE_EXPIRY_PERIOD_MINUTES. When the cache should expire. */
    protected static final int CACHE_EXPIRY_PERIOD_MINUTES = 90;

    /** The Constant LOGGER. */
    private static final Logger LOGGER = getLogger(LdapUserDirectory.class);

    /**
     * Convenience function to convert a map to stream.
     *
     * @param <K> the key type
     * @param <V> the value type
     * @param map the map
     * @return the stream
     */
    private static <K, V> Stream<V> mapToStream(Map<K, V> map) {
        return map.values().stream();
    }

    /** The cached users. */
    protected ConcurrentHashMap<String, DirectoryUser> users;

    /** The directory delegate. */
    protected final DirectoryDelegate delegate;

    /**
     * Instantiates a new ldap user directory.
     *
     * @param delegate the delegate
     */
    @Inject
    public LdapUserDirectory(DirectoryDelegate delegate) {
        this.delegate = delegate;
        /*
         * NOTICE: It is very important during construct to catch all LDAP exceptions. Otherwise the DI will fail
         * completely and the application will NOT start at all
         */
        try {
            refreshCache();
        } catch (AuthenticationException authException) {
            LOGGER.error("LDAP ERROR: Failed to initialize user cache", authException);
        }
    }

    /**
     * Add user to local cache
     * 
     * @param user The directory user to add to the cache
     * @return The result of the cache put operation
     */
    @Override
    public DirectoryUser addUserToCache(DirectoryUser user) {
        return this.users.put(user.getUsername().getUsername(), user);
    }

    /**
     * Authenticate (e.g. during initial login) a given user
     * 
     * @param username - The username to authenticate
     * @param password - The password to authenticate
     * @return The directory user if successful
     */
    @Override
    public DirectoryUser authenticate(String username, String password) {
        return delegate.authenticate(this, username, password);
    }

    /**
     * Get a stream of all users
     * 
     * @return All directory users
     */
    @Override
    public Stream<DirectoryUser> getAllUsers() {
        Stream<DirectoryUser> result = null;
        result = mapToStream(this.users);
        return result;
    }

    /**
     * Gets the directory user from the cache.
     *
     * @param username The target user's username
     * @return The directory user object from cache
     */
    protected DirectoryUser getDirectoryUserFromCache(String username) {
        DirectoryUser cachedUser;
        cachedUser = this.users.get(username);

        if (cachedUser != null) {
            return validateCachedUser(cachedUser);
        }
        return null;
    }

    /**
     * Validate a directory token
     * 
     * @param username The username to validate
     * @param encryptedPassword The password to validate
     * @return true, if a directory token is valid
     */
    @Override
    public boolean isDirectoryTokenValid(String username, String encryptedPassword) {
        return delegate.isDirectoryTokenValid(this, username, encryptedPassword);
    }

    /**
     * Find a user by username
     * 
     * @param username The target user's username
     * @return The user object
     */
    @Override
    public DirectoryUser lookupDirectoryUser(String username) {
        DirectoryUser result = getDirectoryUserFromCache(username);
        if (result != null) {
            return result;
        }
        return delegate.getDirectoryUserByUsername(this, username);
    }

    /**
     * Find a user by username
     * 
     * @param username The username of the target user
     * @return The resulting user object
     */
    @Override
    public UserInfo lookupUser(final Username username) {
        DirectoryUser result = getDirectoryUserFromCache(username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        result = delegate.getDirectoryUserByUsername(this, username.getUsername());
        if (result != null) {
            return result.getUserInfo();
        }
        return null;
    }

    /**
     * Lookup a user by email
     * 
     * @param userEmail the target user's email
     * @return The resulting user object
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {
        DirectoryUser result = null;
        Optional<DirectoryUser> matchingUser = getAllUsers().filter(user -> user.getEmail().equals(userEmail))
                .findFirst();
        if (matchingUser.isPresent()) {
            result = validateCachedUser(matchingUser.get());
        }
        if (result == null) {
            result = delegate.getDirectoryUserByEmail(this, userEmail);
        }
        if (result != null) {
            return result.getUserInfo();
        }
        throw new AuthenticationException(format("Email address does not exist: {0}", userEmail));
    }

    /**
     * Refresh the cache
     */
    @Override
    public void refreshCache() {
        if (this.users == null) {
            this.users = new ConcurrentHashMap<String, DirectoryUser>();
        } else {
            this.users.clear();
        }
        delegate.populateUserCache(this);
    }

    /**
     * Remove a user from the cache
     * 
     * @param The username of the user to remove
     * @return The result of the remove action
     */
    @Override
    public DirectoryUser removeUserFromCache(String username) {
        return this.users.remove(username);
    }

    /**
     * Validate a cached user (check expiration)
     *
     * @param cachedUser the cached user
     * @return the directory user
     */
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
}
