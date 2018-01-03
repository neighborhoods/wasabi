/*******************************************************************************
 * Copyright 2016 Intuit
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
 *******************************************************************************/
package com.nhds.wasabi.userdirectory.impl;

import io.swagger.annotations.ApiModelProperty;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;

import java.util.Date;

import org.apache.commons.lang3.builder.EqualsBuilder;

/**
 * Wrapper class to workaround inability to modify the UserInfo class
 */
public class LdapUser {
    @ApiModelProperty(value = "the user's role", required = false)
    private String role;
    private UserInfo userInfo;
    private long cacheTimestamp;
    protected LdapUser(UserInfo userInfo) {
        super();
        this.userInfo = userInfo;
        Date now = new Date();
        this.cacheTimestamp = now.getTime();
    }
    public LdapUser(UserInfo userInfo, String role) {
        super();
        this.userInfo = userInfo;
        this.role = role;
        Date now = new Date();
        this.cacheTimestamp = now.getTime();
    }
    public Username getUsername() {
        return this.userInfo.getUsername();
    }

    public void setUsername(Username username) {
        this.userInfo.setUsername(username);
    }

    public String getPassword() {
        return this.userInfo.getPassword();
    }

    public void setPassword(String password) {
        this.userInfo.setPassword(password);
    }

    /**
     * @return the userId
     */
    public String getUserId() {
        return this.userInfo.getUserId();
    }

    /**
     * @param userId the userId to set
     */
    public void setUserId(String userId) {
        this.userInfo.setUserId(userId);
    }

    public String getFirstName() {
        return this.userInfo.getFirstName();
    }

    public void setFirstName(String firstName) {
        this.userInfo.setFirstName(firstName);
    }

    public String getLastName() {
        return this.userInfo.getLastName();
    }

    public void setLastName(String lastName) {
        this.userInfo.setLastName(lastName);
    }

    public String getEmail() {
        return this.userInfo.getEmail();
    }

    public void setEmail(String email) {
        this.userInfo.setEmail(email);
    }
    
    public UserInfo getUserInfo(){
        return this.userInfo;
    }
    
    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }
    public String getRole() {
        return this.role;
    }
    protected void setRole(String role) {
        this.role = role;
    }
    @Override
    public String toString() {
        return "LdapUser[UserInfo ["+this.userInfo.toString()+"], role="+this.role+"]";
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null) return false;
        if (obj == this) return true;
        if (!(obj instanceof LdapUser)) {
            return false;
        }

        UserInfo otherUserInfo = ((LdapUser) obj).getUserInfo();
        if(otherUserInfo.equals(this.getUserInfo())) {
            return new EqualsBuilder()
                    .append(role, ((LdapUser) obj).getRole())
                    .isEquals();
        }
        return false;
    }
    public long getCacheTimestamp() {
        return cacheTimestamp;
    }
}
