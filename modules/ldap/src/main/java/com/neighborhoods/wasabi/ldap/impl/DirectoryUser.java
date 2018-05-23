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

import org.apache.commons.lang3.builder.EqualsBuilder;

import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;

import io.swagger.annotations.ApiModelProperty;

/**
 * Simple POJO wrapper class to workaround inability to modify the UserInfo class.
 */
public class DirectoryUser {

    /** The role. */
    @ApiModelProperty(value = "the user's role", required = false)
    private String role;

    /** The user info. */
    private UserInfo userInfo;

    /** The cache timestamp. */
    private long cacheTimestamp;

    /**
     * Instantiates a new directory user.
     *
     * @param userInfo the user info base
     */
    public DirectoryUser(UserInfo userInfo) {
        this.userInfo = userInfo;
        Date now = new Date();
        this.cacheTimestamp = now.getTime();
    }

    /**
     * Instantiates a new directory user.
     *
     * @param userInfo the user info base
     * @param role the role
     */
    public DirectoryUser(UserInfo userInfo, String role) {
        this.userInfo = userInfo;
        this.role = role;
        Date now = new Date();
        this.cacheTimestamp = now.getTime();
    }

    /**
     * Equals operator override
     * 
     * @param object to compare to
     * @return whether this is equal to the target object
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;
        if (obj == this)
            return true;
        if (!(obj instanceof DirectoryUser)) {
            return false;
        }

        UserInfo otherUserInfo = ((DirectoryUser) obj).getUserInfo();
        if (otherUserInfo.equals(this.getUserInfo())) {
            return new EqualsBuilder().append(role, ((DirectoryUser) obj).getRole()).isEquals();
        }
        return false;
    }

    /**
     * Gets the cache timestamp.
     *
     * @return the cache timestamp
     */
    public long getCacheTimestamp() {
        return this.cacheTimestamp;
    }

    /**
     * Gets the email.
     *
     * @return the email
     */
    public String getEmail() {
        return this.userInfo.getEmail();
    }

    /**
     * Gets the first name.
     *
     * @return the first name
     */
    public String getFirstName() {
        return this.userInfo.getFirstName();
    }

    /**
     * Gets the last name.
     *
     * @return the last name
     */
    public String getLastName() {
        return this.userInfo.getLastName();
    }

    /**
     * Gets the password.
     *
     * @return the password
     */
    public String getPassword() {
        return this.userInfo.getPassword();
    }

    /**
     * Gets the role.
     *
     * @return the role
     */
    public String getRole() {
        return this.role;
    }

    /**
     * Gets the user id.
     *
     * @return the userId
     */
    public String getUserId() {
        return this.userInfo.getUserId();
    }

    /**
     * Gets the user info.
     *
     * @return the user info
     */
    public UserInfo getUserInfo() {
        return this.userInfo;
    }

    /**
     * Gets the username.
     *
     * @return the username
     */
    public Username getUsername() {
        return this.userInfo.getUsername();
    }

    /**
     * Sets the email.
     *
     * @param email the new email
     */
    public void setEmail(String email) {
        this.userInfo.setEmail(email);
    }

    /**
     * Sets the first name.
     *
     * @param firstName the new first name
     */
    public void setFirstName(String firstName) {
        this.userInfo.setFirstName(firstName);
    }

    /**
     * Sets the last name.
     *
     * @param lastName the new last name
     */
    public void setLastName(String lastName) {
        this.userInfo.setLastName(lastName);
    }

    /**
     * Sets the password.
     *
     * @param password the new password
     */
    public void setPassword(String password) {
        this.userInfo.setPassword(password);
    }

    /**
     * Sets the role.
     *
     * @param role the new role
     */
    protected void setRole(String role) {
        this.role = role;
    }

    /**
     * Sets the user id.
     *
     * @param userId the userId to set
     */
    public void setUserId(String userId) {
        this.userInfo.setUserId(userId);
    }

    /**
     * Sets the user info.
     *
     * @param userInfo the new user info
     */
    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    /**
     * Sets the username.
     *
     * @param username the new username
     */
    public void setUsername(Username username) {
        this.userInfo.setUsername(username);
    }

    /**
     * Converts this object to a string representation
     * 
     * @return String representation of the object
     */
    @Override
    public String toString() {
        return "DirectoryUser[UserInfo [" + this.userInfo.toString() + "], role=" + this.role + "]";
    }
}
