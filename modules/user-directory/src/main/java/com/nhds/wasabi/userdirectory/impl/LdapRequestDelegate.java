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
package com.nhds.wasabi.userdirectory.impl;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.BCrypt;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;

import static com.intuit.autumn.utils.PropertyFactory.create;
import static com.intuit.autumn.utils.PropertyFactory.getProperty;

public class LdapRequestDelegate implements LdapDelegateInterface{
    private static final int LDAP_BCRYPT_ROUNDS = 4;
    private static final long ONE_MINUTE_IN_MILLIS=60000;
    private static final int CACHE_EXPIRY_PERIOD_MINUTES = 90;
    private LdapConfig config;
    /**
     * Private Inner Class for managing LDAP configuration details 
     */
    private class LdapConfig {
        public static final String PROPERTY_NAME = "/userDirectory.properties";
        public static final String ROLE_NONE = "none";
        public static final String ROLE_ADMIN = "admin";
        public static final String ROLE_SUPER_ADMIN = "superadmin";
        public static final String ROLE_WRITER = "readwrite";
        public static final String ROLE_READER = "readonly";
        private String ldapHost;
        private int ldapPort;
        private boolean useSecureConnection;
        // Base Distinguished Name (e.g. dc=example,dc=com)
        private String baseDN;
        // Wasabi Distinguished Name (e.g. cn=Wasabi,dc=example,dc=com)
        private String wasabiDN;
        // Type of entity used for login (e.g. uid)
        private String loginEntity;
        // Search key within Wasabi DN to attribute membership to a user (e.g. member)
        private String memberKey;
        // Attribute key used to describe role (e.g. cn)
        private String roleAttributeKey;
        private String infoDN;
        private String infoPassword;
        private String superAdminGroup;
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
        public String getInfoDN() {
            return infoDN;
        }
        public void setInfoDN(String infoDN) {
            this.infoDN = infoDN;
        }
        public String getInfoPassword() {
            return infoPassword;
        }
        public void setInfoPassword(String infoPassword) {
            this.infoPassword = infoPassword;
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
        public String getMemberKey() {
            return memberKey;
        }
        public void setMemberKey(String memberKey) {
            this.memberKey = memberKey;
        }
        public String getRoleSearchKey() {
            return memberKey+"="+loginEntity+"=";
        }
        public String getRoleAttributeKey() {
            return roleAttributeKey;
        }
        public void setRoleAttributeKey(String roleAttributeKey) {
            this.roleAttributeKey = roleAttributeKey;
        }
        public String getSuperAdminGroup() {
            return superAdminGroup;
        }
        public void setSuperAdminGroup(String superAdminGroup) {
            this.superAdminGroup = superAdminGroup;
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
            Properties properties = create(PROPERTY_NAME, LdapRequestDelegate.class);
            this.setLdapHost(getProperty("ldap.host",properties));
            this.setLdapPort(Integer.parseInt(getProperty("ldap.port", properties, "10389")));
            this.setUseSecureConnection(Boolean.parseBoolean(getProperty("ldap.port", properties, "false")));
            this.setBaseDN(getProperty("ldap.dn.base",properties));
            this.setWasabiDN(getProperty("ldap.dn.wasabi",properties));
            this.setInfoDN(getProperty("ldap.dn.info",properties));
            this.setInfoPassword(getProperty("ldap.dn.info.password",properties));
            this.setLoginEntity(getProperty("ldap.login.attribute",properties, "uid"));
            this.setMemberKey(getProperty("ldap.member.attribute",properties, "member"));
            this.setRoleAttributeKey(getProperty("ldap.role.attribute",properties, "cn"));
            this.setAdminGroup(getProperty("ldap.group.admin",properties).toLowerCase());
            this.setSuperAdminGroup(getProperty("ldap.group.superadmin",properties).toLowerCase());
            this.setReaderGroup(getProperty("ldap.group.reader",properties).toLowerCase());
            this.setWriterGroup(getProperty("ldap.group.writer",properties).toLowerCase());
            this.setPersonAttrEmail(getProperty("ldap.person.email",properties,"mail"));
            this.setPersonAttrFirst(getProperty("ldap.person.first",properties,"givenname"));
            this.setPersonAttrLast(getProperty("ldap.person.last",properties,"sn"));
            /*this.setLdapHost("docker.for.mac.localhost");
            this.setLdapPort(10389);
            this.setUseSecureConnection(false);
            this.setBaseDN("dc=neighborhoods,dc=com");
            this.setWasabiDN("cn=Wasabi,dc=neighborhoods,dc=com");
            this.setInfoDN("cn=readonly,dc=neighborhoods,dc=com");
            this.setInfoPassword("Pelican555");
            this.setLoginEntity("uid");
            this.setMemberKey("member");
            this.setRoleAttributeKey("cn");
            this.setAdminGroup("admin");
            this.setSuperAdminGroup("superadmin");
            this.setReaderGroup("reader");
            this.setWriterGroup("writer");
            this.setPersonAttrEmail("mail");
            this.setPersonAttrFirst("givenname");
            this.setPersonAttrLast("sn");*/
        }
        public String translateRole(String providedRole) {
            if(providedRole==null) {
                return LdapConfig.ROLE_NONE;
            }
            else providedRole = providedRole.toLowerCase();
            if(this.getSuperAdminGroup().equals(providedRole)){
                return LdapConfig.ROLE_SUPER_ADMIN;
            }
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
    public void getUserCache(LdapUserDirectory userDirectory) throws AuthenticationException {
        HashMap<String,LdapUser> users = new HashMap<String,LdapUser>();
        // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the connection during exceptional behavior 
        try (LdapConnection connection = new LdapNetworkConnection( this.config.getLdapHost(), this.config.getLdapPort(), this.config.isUseSecureConnection() )){
            connection.bind(this.config.getInfoDN(),this.config.getInfoPassword());
            if(connection.isConnected() && connection.isAuthenticated()){
                // Create the SearchRequest object
                SearchRequest req = new SearchRequestImpl();
                req.setScope( SearchScope.SUBTREE );
                req.addAttributes( this.config.getRoleAttributeKey() );
                req.addAttributes( this.config.getMemberKey() );
                req.setTimeLimit( 0 );
                req.setBase( new Dn( this.config.getWasabiDN() ) );
                req.setFilter( "(objectclass=*)" );
                try(SearchCursor searchCursor = connection.search( req )) {
                    while ( searchCursor.next() )
                    {
                        Response response = searchCursor.get();
                        // process the SearchResultEntry
                        if ( response instanceof SearchResultEntry )
                        {
                            Entry resultEntry = ( ( SearchResultEntry ) response ).getEntry();
                            Attribute group = resultEntry.get(this.config.getRoleAttributeKey());
                            if(group==null || LdapConfig.ROLE_NONE.equals(this.config.translateRole(group.getString()))) {
                                continue;
                            }
                            String role = this.config.translateRole(group.getString());
                            Attribute memberAttribute = resultEntry.get(this.config.getMemberKey());
                            Iterator<Value<?>> members = memberAttribute.iterator();
                            while(members.hasNext()) {
                                String member = members.next().getString();
                                if(member.contains("=")) {
                                    member = member.substring(member.indexOf("=")+1);
                                }
                                try(EntryCursor cursor = connection.search( this.config.getBaseDN(), "("+this.config.getLoginEntity()+"="+member+")", SearchScope.ONELEVEL )){
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
                                        else email = member+"@unknown.com";
                                        UserInfo result = new UserInfo.Builder(UserInfo.Username.valueOf(member))
                                                .withFirstName(firstName)
                                                .withLastName(lastName)
                                                .withEmail(email)
                                                .withUserId(member)
                                                .build();
                                        users.put(member, new LdapUser(result,role));
                                    } 
                                }
                            }
                        }
                    }
                }
            }
        } catch (CursorException e) {
            throw new AuthenticationException( "LDAP Search Query Failed!" );
        }catch(LdapAuthenticationException authException) {
            throw new AuthenticationException( "LDAP Authentication Failed!" );
        }catch (LdapException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        } catch (IOException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        }
        userDirectory.setUserCache(users);
    }
    public LdapUser getUserInfoByUsername(String username) throws AuthenticationException {
        // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the connection during exceptional behavior 
        try (LdapConnection connection = new LdapNetworkConnection( this.config.getLdapHost(), this.config.getLdapPort(), this.config.isUseSecureConnection() )){
            connection.bind(this.config.getInfoDN(),this.config.getInfoPassword());
            if(connection.isConnected() && connection.isAuthenticated()){
                String role = null;
                // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the cursor during exceptional behavior
                try(EntryCursor cursor = connection.search( this.config.getWasabiDN(), "("+this.config.getRoleSearchKey()+username+")", SearchScope.ONELEVEL )){
                    for ( Entry entry : cursor ) {
                        Attribute attributeRole = entry.get(this.config.getRoleAttributeKey());
                        if(attributeRole!=null) {
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    if(role==null || LdapConfig.ROLE_NONE.equals(role)) {
                        return null;
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
                                .build();
                        return new LdapUser(result,role);
                    } 
                }
            }
        } catch(LdapAuthenticationException authException) {
            throw new AuthenticationException( "LDAP Authentication Failed for getUserInfoByUsername" );
        }catch (LdapException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        } catch (IOException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        }
        return null;
    }
    public LdapUser getUserInfoByEmail(String email) throws AuthenticationException {
        // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the connection during exceptional behavior 
        try (LdapConnection connection = new LdapNetworkConnection( this.config.getLdapHost(), this.config.getLdapPort(), this.config.isUseSecureConnection() )){
            connection.bind(this.config.getInfoDN(),this.config.getInfoPassword());
            if(connection.isConnected() && connection.isAuthenticated()){
                // Cannot verify role by email?
                try(EntryCursor cursor = connection.search( this.config.getBaseDN(), "("+this.config.getPersonAttrEmail()+"="+email+")", SearchScope.ONELEVEL )){
                    for ( Entry entry : cursor ) {
                        String firstName = "";
                        String lastName = "";
                        //String email = "";
                        Attribute attr = entry.get(this.config.getPersonAttrFirst());
                        if(attr!=null) {
                            firstName = attr.getString();
                        }
                        attr = entry.get(this.config.getPersonAttrLast());
                        if(attr!=null) {
                            lastName = attr.getString();
                        }
                        attr = entry.get(this.config.getLoginEntity());
                        String username = null;
                        if(attr!=null) {
                            username = attr.getString();
                        }
                        else throw new AuthenticationException("LDAP email does not map to an actual username");
                        UserInfo result = new UserInfo.Builder(UserInfo.Username.valueOf(username))
                                .withFirstName(firstName)
                                .withLastName(lastName)
                                .withEmail(email)
                                .withUserId(username)
                                .build();
                        return new LdapUser(result);
                    } 
                }
            }
        } catch (LdapException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        } catch (IOException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        }
        return null;
    }
    public LdapUser authenticate(LdapUserDirectory ldapUserDirectory, String username, String password) throws AuthenticationException {
        // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the connection during exceptional behavior 
        try (LdapConnection connection = new LdapNetworkConnection( this.config.getLdapHost(), this.config.getLdapPort(), this.config.isUseSecureConnection() )){
            connection.bind(this.config.getLoginEntity()+"="+username+","+this.config.getBaseDN(),password);
            if(connection.isConnected() && connection.isAuthenticated()){
                String role = null;
                // NOTICE: To avoid memory leaks, use try-with-resources statement to automatically close the cursor during exceptional behavior
                try(EntryCursor cursor = connection.search( this.config.getWasabiDN(), "("+this.config.getRoleSearchKey()+username+")", SearchScope.ONELEVEL )){
                    for ( Entry entry : cursor ) {
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
                                .withPassword(encryptPassword(password))
                                .build();
                        LdapUser ldapUser = new LdapUser(result,role);
                        ldapUserDirectory.addUserToCache(ldapUser);
                        return ldapUser;
                        //System.out.println( "firstName="+firstName+", lastName="+lastName+", email=" +email);
                    } 
                }
            }
        } catch(LdapAuthenticationException authException) {
            throw new AuthenticationException( "LDAP Authentication Failed!" );
        }catch (LdapException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        } catch (IOException e) {
            throw new AuthenticationException( "Error connecting to LDAP. Please contact your administrator." );
        }
        return null;
    }
    public String encryptPassword(String password) {
        return BCrypt.hashPw(password, BCrypt.gensalt(LDAP_BCRYPT_ROUNDS));
    }
    public LdapRequestDelegate(){
        this.config = new LdapConfig();
    }
    private static class SingletonHelper{
        private static final LdapRequestDelegate INSTANCE = new LdapRequestDelegate();
    }
    public static LdapRequestDelegate getInstance(){
        return SingletonHelper.INSTANCE;
    }
    public boolean isLdapTokenValid(LdapUserDirectory ldapUserDirectory, String username, String password) {
        try {
            //Encoded passwords are only in the cache 
            LdapUser userInfo = ldapUserDirectory.lookupLdapUser(UserInfo.Username.valueOf(username));
            if(userInfo!=null && userInfo.getPassword()!=null)
            {
                Date expirationDate=new Date(userInfo.getCacheTimestamp() + (CACHE_EXPIRY_PERIOD_MINUTES * ONE_MINUTE_IN_MILLIS));
                Date now = new Date();
                if(now.after(expirationDate)) {
                    ldapUserDirectory.removeUserFromCache(username);
                    return false;
                }
                return userInfo.getPassword().equals(password);
            }
            return false;
        } catch (AuthenticationException ae) {
            return false;
        }
    }
}
