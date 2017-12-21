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

package com.nhds.wasabi.userdirectory.impl;

import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.userdirectory.UserDirectory;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

/**
 * Noop implementation for the UserDirectory, by default we will return super admin user
 */
public class LdapUserDirectory implements UserDirectory {
    private HashMap<String,LdapUser> users;
    private LdapDelegateInterface ldap;
    /**
     * @param users a list of user credentials
     */
    public LdapUserDirectory() {
        this.users = new HashMap<String,LdapUser>();
        this.ldap = LdapRequestDelegate.getInstance();
        refreshCache();
    }
    public void addUserToCache(LdapUser user) {
        this.users.put(user.getUsername().getUsername(),user);
    }
    /**
     * @param userEmail a user email address to check if it exists
     * @return a userinfo contain the user with that email address
     * @see UserDirectory#lookupUserByEmail(java.lang.String)
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {
        Iterator<Entry<String,LdapUser>> iterator = this.users.entrySet().iterator();
        while (iterator.hasNext() ) {
            Entry<String,LdapUser> item = iterator.next();
            if(userEmail.equals(item.getValue().getEmail())) {
                return item.getValue().getUserInfo();
            }
        }
        LdapUser result = this.ldap.getUserInfoByEmail(userEmail);
        if(result != null) {
            addUserToCache(result);
        }
        return null;
    }
    public void removeUserFromCache(String username) {
        this.users.remove(username);
    }
    @Override
    public UserInfo lookupUser(final Username username) {
        LdapUser result = this.users.get(username.getUsername());
        if(result!=null) {
            return result.getUserInfo();
        }
        result = this.ldap.getUserInfoByUsername(username.getUsername());
        if(result != null) {
            addUserToCache(result);
            return result.getUserInfo();
        }
        return null;
    }
    
    public LdapUser lookupLdapUser(final Username username) {
        LdapUser result = this.users.get(username.getUsername());
        if(result!=null) {
            return result;
        }
        result = this.ldap.getUserInfoByUsername(username.getUsername());
        if(result != null) {
            addUserToCache(result);
            return result;
        }
        return null;
    }
    public HashMap<String, LdapUser> getUsers() {
        return this.users;
    }
    public void setUserCache(HashMap<String, LdapUser> userCache) {
        this.users = userCache;
    }
    public void refreshCache() {
        ldap.getUserCache(this);
    }
    public boolean isLdapTokenValid(String username, String encryptedPassword) {
        return ldap.isLdapTokenValid(this, username, encryptedPassword);
    }
    public LdapUser authenticate(String username, String password) {
        return ldap.authenticate(this,username,password);
    }
}
