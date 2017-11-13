/*******************************************************************************
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
 *******************************************************************************/
package com.nhds.wasabi.authentication.impl;

import java.io.IOException;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;

public class LdapRequestDelegate {
    private LdapConfig config;
    /**
     * Private Inner Class for managing LDAP configuration details 
     */
    private class LdapConfig {
        public static final String ROLE_NONE = "none";
        public static final String ROLE_ADMIN = "admin";
        public static final String ROLE_WRITER = "writer";
        public static final String ROLE_READER = "reader";
        private String ldapHost;
        private int ldapPort;
        private boolean useSecureConnection;
        // Base Distinguished Name (e.g. dc=example,dc=com)
        private String baseDN;
        // Wasabi Distinguished Name (e.g. cn=Wasabi,dc=example,dc=com)
        private String wasabiDN;
        // Type of entity used for login (e.g. uid)
        private String loginEntity;
        // Search key within Wasabi DN to find user's role group (e.g. member=uid=)
        private String roleSearchKey;
        // Attribute key used to describe role (e.g. cn)
        private String roleAttributeKey;
        private String adminGroup;
        private String readerGroup;
        private String writerGroup;
        private String personAttrEmail;
        private String personAttrFirst;
        private String personAttrLast;;
        public String getLdapHost() {
            return ldapHost;
        }
        public void setLdapHost(String ldapHost) {
            this.ldapHost = ldapHost;
        }
        public int getLdapPort() {
            return ldapPort;
        }
        public void setLdapPort(int ldapPort) {
            this.ldapPort = ldapPort;
        }
        public boolean isUseSecureConnection() {
            return useSecureConnection;
        }
        public void setUseSecureConnection(boolean useSecureConnection) {
            this.useSecureConnection = useSecureConnection;
        }
        public String getBaseDN() {
            return baseDN;
        }
        public void setBaseDN(String baseDN) {
            this.baseDN = baseDN;
        }
        public String getWasabiDN() {
            return wasabiDN;
        }
        public void setWasabiDN(String wasabiDN) {
            this.wasabiDN = wasabiDN;
        }
        public String getLoginEntity() {
            return loginEntity;
        }
        public void setLoginEntity(String loginEntity) {
            this.loginEntity = loginEntity;
        }
        public String getRoleSearchKey() {
            return roleSearchKey;
        }
        public void setRoleSearchKey(String roleSearchKey) {
            this.roleSearchKey = roleSearchKey;
        }
        public String getRoleAttributeKey() {
            return roleAttributeKey;
        }
        public void setRoleAttributeKey(String roleAttributeKey) {
            this.roleAttributeKey = roleAttributeKey;
        }
        public String getAdminGroup() {
            return adminGroup;
        }
        public void setAdminGroup(String adminGroup) {
            this.adminGroup = adminGroup;
        }
        public String getReaderGroup() {
            return readerGroup;
        }
        public void setReaderGroup(String readerGroup) {
            this.readerGroup = readerGroup;
        }
        public String getWriterGroup() {
            return writerGroup;
        }
        public void setWriterGroup(String writerGroup) {
            this.writerGroup = writerGroup;
        }
        public String getPersonAttrEmail() {
            return personAttrEmail;
        }
        public void setPersonAttrEmail(String personAttrEmail) {
            this.personAttrEmail = personAttrEmail;
        }
        public String getPersonAttrFirst() {
            return personAttrFirst;
        }
        public void setPersonAttrFirst(String personAttrFirst) {
            this.personAttrFirst = personAttrFirst;
        }
        public String getPersonAttrLast() {
            return personAttrLast;
        }
        public void setPersonAttrLast(String personAttrLast) {
            this.personAttrLast = personAttrLast;
        }
        public LdapConfig() {
            this.setLdapHost("localhost");
            this.setLdapPort(10389);
            this.setUseSecureConnection(false);
            this.setBaseDN("dc=neighborhoods,dc=com");
            this.setLoginEntity("uid");
            this.setWasabiDN("cn=Wasabi,dc=neighborhoods,dc=com");
            this.setRoleSearchKey("member=uid=");
            this.setRoleAttributeKey("cn");
            // TODO: When reading property make these lower case
            this.setAdminGroup("admin");
            this.setReaderGroup("reader");
            this.setWriterGroup("writer");
            this.setPersonAttrEmail("mail");
            this.setPersonAttrFirst("givenname");
            this.setPersonAttrLast("sn");
        }
        public String translateRole(String providedRole) {
            if(providedRole==null) {
                return LdapConfig.ROLE_NONE;
            }
            else providedRole = providedRole.toLowerCase();
            if(this.getAdminGroup().equals(providedRole)){
                return LdapConfig.ROLE_ADMIN;
            } else if(this.getWriterGroup().equals(providedRole)) {
                return LdapConfig.ROLE_WRITER;
            } else if(this.getReaderGroup().equals(providedRole)) {
                return LdapConfig.ROLE_READER;
            }
            return LdapConfig.ROLE_NONE;
        }
    }
    public UserInfo authenticate(String username, String password) throws AuthenticationException {
        // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the connection during exceptional behavior 
        try (LdapConnection connection = new LdapNetworkConnection( this.config.getLdapHost(), this.config.getLdapPort(), this.config.isUseSecureConnection() )){
            connection.bind(this.config.getLoginEntity()+"="+username+","+this.config.getBaseDN(),password);
            if(connection.isConnected() && connection.isAuthenticated()){
                // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the cursor during exceptional behavior
                try(EntryCursor cursor = connection.search( this.config.getWasabiDN(), "("+this.config.getRoleSearchKey()+username+")", SearchScope.ONELEVEL )){
                    String role = null;
                    for ( Entry entry : cursor ) {
                        System.out.println( entry );
                        Attribute attributeRole = entry.get(this.config.getRoleAttributeKey());
                        if(attributeRole!=null) {
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    if(role==null || LdapConfig.ROLE_NONE.equals(role)) {
                        throw new AuthenticationException( "You do not have access to Wasabi. Please contact your Administrator for assistance." );
                    }
                }
                try(EntryCursor cursor = connection.search( this.config.getBaseDN(), "("+this.config.getLoginEntity()+"="+username+")", SearchScope.ONELEVEL )){
                    for ( Entry entry : cursor ) {
                        String firstName = "";
                        String lastName = "";
                        String email = "";
                        Attribute attr = entry.get(this.config.getPersonAttrFirst());
                        if(attr!=null) {
                            firstName = attr.getString();
                        }
                        attr = entry.get(this.config.getPersonAttrLast());
                        if(attr!=null) {
                            lastName = attr.getString();
                        }
                        attr = entry.get(this.config.getPersonAttrEmail());
                        if(attr!=null) {
                            email = attr.getString();
                        }
                        else email = username+"@unknown.com";
                        UserInfo result = new UserInfo.Builder(UserInfo.Username.valueOf(username))
                                .withFirstName(firstName)
                                .withLastName(lastName)
                                .withEmail(email)
                                .withUserId(username)
                                //.withPassword()
                                .build();
                        return result;
                        //System.out.println( "firstName="+firstName+", lastName="+lastName+", email=" +email);
                    } 
                }
            }
        } catch(LdapAuthenticationException authException) {
            throw new AuthenticationException( "Authentication Failed!" );
        }catch (LdapException e) {
            throw new AuthenticationException( "Error connecting to Ldap. Please contact your administrator." );
        } catch (IOException e) {
            throw new AuthenticationException( "Error connecting to Ldap. Please contact your administrator." );
        }
        return null;
    }
    private LdapRequestDelegate(){
        this.config = new LdapConfig();
    }
    private static class SingletonHelper{
        private static final LdapRequestDelegate INSTANCE = new LdapRequestDelegate();
    }
    public static LdapRequestDelegate getInstance(){
        return SingletonHelper.INSTANCE;
    }
}
