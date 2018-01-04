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

import java.io.IOException;
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
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
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
import com.nhds.wasabi.ldap.CachedUserDirectory;
import com.nhds.wasabi.ldap.DirectoryDelegate;

import static com.intuit.autumn.utils.PropertyFactory.create;
import static com.intuit.autumn.utils.PropertyFactory.getProperty;

public class LdapDelegate implements DirectoryDelegate {
    private static final int LDAP_BCRYPT_ROUNDS = 7;
    private static SearchRequest userCacheSearchRequest;
    private LdapConfig config;

    /**
     * Private Inner Class for managing LDAP configuration details
     */
    private class LdapConfig {
        public static final String PROPERTY_NAME = "/ldap.properties";
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
        private String membershipAttribute;
        // Attribute key used to describe role (e.g. cn)
        private String roleAttribute;
        private String infoDN;
        private String infoPassword;
        private String superAdminGroup;
        private String adminGroup;
        private String readerGroup;
        private String writerGroup;
        private String personEmailAttribute;
        private String personFirstNameAttribute;
        private String personLastNameAttribute;;

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

        public String getMembershipAttribute() {
            return membershipAttribute;
        }

        public void setMembershipAttribute(String membershipAttribute) {
            this.membershipAttribute = membershipAttribute;
        }

        public String getRoleSearchAttribute() {
            return membershipAttribute + "=" + loginEntity + "=";
        }

        public String getRoleAttribute() {
            return roleAttribute;
        }

        public void setRoleAttribute(String roleAttribute) {
            this.roleAttribute = roleAttribute;
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

        public String getPersonEmailAttribute() {
            return personEmailAttribute;
        }

        public void setPersonEmailAttribute(String personEmailAttribute) {
            this.personEmailAttribute = personEmailAttribute;
        }

        public String getPersonFirstNameAttribute() {
            return personFirstNameAttribute;
        }

        public void setPersonFirstNameAttribute(String personFirstNameAttribute) {
            this.personFirstNameAttribute = personFirstNameAttribute;
        }

        public String getPersonLastNameAttribute() {
            return personLastNameAttribute;
        }

        public void setPersonLastNameAttribute(String personLastNameAttribute) {
            this.personLastNameAttribute = personLastNameAttribute;
        }

        public LdapConfig() {
            Properties properties = create(PROPERTY_NAME, LdapDelegate.class);
            this.setLdapHost(getProperty("ldap.host", properties));
            this.setLdapPort(Integer.parseInt(getProperty("ldap.port", properties, "10389")));
            this.setUseSecureConnection(Boolean.parseBoolean(getProperty("ldap.secure", properties, "false")));
            this.setBaseDN(getProperty("ldap.dn.base", properties));
            this.setWasabiDN(getProperty("ldap.dn.wasabi", properties));
            this.setInfoDN(getProperty("ldap.dn.info", properties));
            this.setInfoPassword(getProperty("ldap.dn.info.password", properties));
            this.setLoginEntity(getProperty("ldap.login.attribute", properties, "uid"));
            this.setMembershipAttribute(getProperty("ldap.member.attribute", properties, "member"));
            this.setRoleAttribute(getProperty("ldap.role.attribute", properties, "cn"));
            this.setAdminGroup(getProperty("ldap.group.admin", properties, "admin").toLowerCase());
            this.setSuperAdminGroup(getProperty("ldap.group.superadmin", properties, "superadmin").toLowerCase());
            this.setReaderGroup(getProperty("ldap.group.reader", properties, "reader").toLowerCase());
            this.setWriterGroup(getProperty("ldap.group.writer", properties, "writer").toLowerCase());
            this.setPersonEmailAttribute(getProperty("ldap.person.email.attribute", properties, "mail"));
            this.setPersonFirstNameAttribute(getProperty("ldap.person.first.attribute", properties, "givenname"));
            this.setPersonLastNameAttribute(getProperty("ldap.person.last.attribute", properties, "sn"));
        }

        public String translateRole(String providedRole) {
            if (providedRole == null) {
                return LdapConfig.ROLE_NONE;
            } else
                providedRole = providedRole.toLowerCase();
            if (this.getSuperAdminGroup().equals(providedRole)) {
                return LdapConfig.ROLE_SUPER_ADMIN;
            }
            if (this.getAdminGroup().equals(providedRole)) {
                return LdapConfig.ROLE_ADMIN;
            }
            if (this.getWriterGroup().equals(providedRole)) {
                return LdapConfig.ROLE_WRITER;
            }
            if (this.getReaderGroup().equals(providedRole)) {
                return LdapConfig.ROLE_READER;
            }
            return LdapConfig.ROLE_NONE;
        }
    }

    protected LdapConnection getLdapConnection() {
        return new LdapNetworkConnection(this.config.getLdapHost(), this.config.getLdapPort(),
                this.config.isUseSecureConnection());
    }

    protected SearchRequest getUserCacheSearchRequest() throws LdapException {
        if (userCacheSearchRequest == null) {
            userCacheSearchRequest = new SearchRequestImpl();
            userCacheSearchRequest.setScope(SearchScope.SUBTREE);
            userCacheSearchRequest.addAttributes(this.config.getRoleAttribute());
            userCacheSearchRequest.addAttributes(this.config.getMembershipAttribute());
            userCacheSearchRequest.setTimeLimit(0);
            userCacheSearchRequest.setBase(new Dn(this.config.getWasabiDN()));
            userCacheSearchRequest.setFilter("(objectclass=*)");
        }
        return userCacheSearchRequest;
    }

    public void populateUserCache(CachedUserDirectory userDirectory) throws AuthenticationException {
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                try (SearchCursor searchCursor = connection.search(getUserCacheSearchRequest())) {
                    while (searchCursor.next()) {
                        Response response = searchCursor.get();
                        // process the SearchResultEntry
                        if (response instanceof SearchResultEntry) {
                            Entry resultEntry = ((SearchResultEntry) response).getEntry();
                            Attribute group = resultEntry.get(this.config.getRoleAttribute());
                            if (group == null
                                    || LdapConfig.ROLE_NONE.equals(this.config.translateRole(group.getString()))) {
                                continue;
                            }
                            String role = this.config.translateRole(group.getString());
                            Attribute memberAttribute = resultEntry.get(this.config.getMembershipAttribute());
                            Iterator<Value<?>> members = memberAttribute.iterator();
                            while (members.hasNext()) {
                                String member = members.next().getString();
                                if (member.contains("=")) {
                                    member = member.substring(member.indexOf("=") + 1);
                                }
                                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                                        "(" + this.config.getLoginEntity() + "=" + member + ")",
                                        SearchScope.ONELEVEL)) {
                                    DirectoryUser user = getDirectoryUserViaCursor(cursor);
                                    if (user != null) {
                                        user.setRole(role);
                                        userDirectory.addUserToCache(user);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (CursorException e) {
            throw new AuthenticationException("LDAP Search Query Failed!");
        } catch (LdapAuthenticationException authException) {
            throw new AuthenticationException("LDAP Authentication Failed!");
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        } catch (IOException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        }
    }

    public DirectoryUser getDirectoryUserByUsername(CachedUserDirectory userDirectory, String username)
            throws AuthenticationException {
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                String role = null;
                try (EntryCursor cursor = connection.search(this.config.getWasabiDN(),
                        "(" + this.config.getRoleSearchAttribute() + username + ")", SearchScope.ONELEVEL)) {
                    for (Entry entry : cursor) {
                        Attribute attributeRole = entry.get(this.config.getRoleAttribute());
                        if (attributeRole != null) {
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    if (role == null || LdapConfig.ROLE_NONE.equals(role)) {
                        return null;
                    }
                }
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getLoginEntity() + "=" + username + ")", SearchScope.ONELEVEL)) {
                    DirectoryUser DirectoryUser = getDirectoryUserViaCursor(cursor);
                    if (DirectoryUser != null) {
                        DirectoryUser.setRole(role);
                        userDirectory.addUserToCache(DirectoryUser);
                        return DirectoryUser;
                    }
                }
            }
        } catch (LdapAuthenticationException authException) {
            throw new AuthenticationException("LDAP Authentication Failed for getUserInfoByUsername");
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        } catch (IOException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        }
        return null;
    }

    protected LdapConnection getLdapInfoConnection() throws LdapException {
        LdapConnection connection = getLdapConnection();
        connection.bind(this.config.getInfoDN(), this.config.getInfoPassword());
        return connection;
    }

    protected DirectoryUser getDirectoryUserViaCursor(EntryCursor cursor) throws LdapInvalidAttributeValueException {
        for (Entry entry : cursor) {
            String firstName = "";
            String lastName = "";
            String email = "";
            String username = null;
            Attribute attr = entry.get(this.config.getPersonFirstNameAttribute());
            if (attr != null) {
                firstName = attr.getString();
            }
            attr = entry.get(this.config.getPersonLastNameAttribute());
            if (attr != null) {
                lastName = attr.getString();
            }
            attr = entry.get(this.config.getLoginEntity());
            if (attr != null) {
                username = attr.getString();
            } else {
                throw new AuthenticationException("LDAP result does not contain login entity");
            }
            attr = entry.get(this.config.getPersonEmailAttribute());
            if (attr != null) {
                email = attr.getString();
            }
            return new DirectoryUser(new UserInfo.Builder(UserInfo.Username.valueOf(username)).withFirstName(firstName)
                    .withLastName(lastName).withEmail(email).withUserId(username).build());
        }
        return null;
    }

    public DirectoryUser getDirectoryUserByEmail(CachedUserDirectory userDirectory, String email) throws AuthenticationException {
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getPersonEmailAttribute() + "=" + email + ")", SearchScope.ONELEVEL)) {
                    // Note: Because this method cannot verify role access by email and lookups by email are only
                    // performed for authorization assignments, this is intentionally not cached
                    return getDirectoryUserViaCursor(cursor);
                }
            }
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        } catch (IOException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        }
        return null;
    }

    public DirectoryUser authenticate(CachedUserDirectory userDirectory, String username, String password)
            throws AuthenticationException {
        try (LdapConnection connection = getLdapConnection()) {
            connection.bind(this.config.getLoginEntity() + "=" + username + "," + this.config.getBaseDN(), password);
            if (connection.isConnected() && connection.isAuthenticated()) {
                String role = null;
                try (EntryCursor cursor = connection.search(this.config.getWasabiDN(),
                        "(" + this.config.getRoleSearchAttribute() + username + ")", SearchScope.ONELEVEL)) {
                    for (Entry entry : cursor) {
                        Attribute attributeRole = entry.get(this.config.getRoleAttribute());
                        if (attributeRole != null) {
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    if (role == null || LdapConfig.ROLE_NONE.equals(role)) {
                        throw new AuthenticationException(
                                "You do not have access to Wasabi. Please contact your Administrator for assistance.");
                    }
                }
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getLoginEntity() + "=" + username + ")", SearchScope.ONELEVEL)) {
                    DirectoryUser ldapUser = getDirectoryUserViaCursor(cursor);
                    if(ldapUser!=null) {
                        ldapUser.setRole(role);
                        ldapUser.setPassword(encryptPassword(password));
                        userDirectory.addUserToCache(ldapUser);
                    }
                    return ldapUser;
                }
            }
        } catch (LdapAuthenticationException authException) {
            throw new AuthenticationException("LDAP Authentication Failed!");
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        } catch (IOException e) {
            throw new AuthenticationException("Error connecting to LDAP. Please contact your administrator.");
        }
        return null;
    }

    private String encryptPassword(String password) {
        return BCrypt.hashPw(password, BCrypt.gensalt(LDAP_BCRYPT_ROUNDS));
    }

    public LdapDelegate() {
        this.config = new LdapConfig();
    }

    private static class SingletonHelper {
        private static final LdapDelegate INSTANCE = new LdapDelegate();
    }

    public static LdapDelegate getInstance() {
        return SingletonHelper.INSTANCE;
    }

    public boolean isDirectoryTokenValid(CachedUserDirectory userDirectory, String username, String encodedPassword) {
        try {
            // Encoded passwords are only in the cache
            DirectoryUser userInfo = userDirectory.lookupDirectoryUser(username);
            if (userInfo != null && userInfo.getPassword() != null) {
                return userInfo.getPassword().equals(encodedPassword);
            }
        } catch (AuthenticationException ae) {
            return false;
        }
        return false;
    }
}
