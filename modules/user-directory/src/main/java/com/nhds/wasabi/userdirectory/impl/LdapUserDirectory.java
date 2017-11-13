/**
 * Copyright 2017 Neighborhoods.com
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 *
 */
package com.nhds.wasabi.userdirectory.impl;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectory;

import java.util.ArrayList;

import static java.text.MessageFormat.format;

/**
 * Noop implementation for the UserDirectory, by default we will return super admin user
 */
public class LdapUserDirectory implements UserDirectory {


    private ArrayList<UserInfo> users;

    /**
     * @param users a list of user credentials
     */
    public LdapUserDirectory() {
        this.users = new ArrayList<UserInfo>();
    }
    public void addUserToCache(UserInfo user) {
        this.users.add(user);
    }
    /**
     * @param userEmail a user email address to check if it exists
     * @return a userinfo contain the user with that email address
     * @see UserDirectory#lookupUserByEmail(java.lang.String)
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {
        // Check cached users first
        for (UserInfo user : users) {
            if (user.getEmail().equals(userEmail)) {
                return user;
            }
        }
        return null;
    }

    @Override
    public UserInfo lookupUser(final Username username) {
        final String usernameString = username.getUsername();

        for (UserInfo user : users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }
}
