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

import static com.intuit.autumn.utils.PropertyFactory.create;
import static com.intuit.autumn.utils.PropertyFactory.getProperty;
import static org.slf4j.LoggerFactory.getLogger;

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
import org.slf4j.Logger;

import com.google.inject.Singleton;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.neighborhoods.wasabi.ldap.CachedUserDirectory;
import com.neighborhoods.wasabi.ldap.DirectoryDelegate;

/**
 * The Class LdapDelegate.
 * 
 * This is the default implementation of the DirectoryDelegate interface. All authentication and authorization calls
 * have been collapsed into a single delegate. This is the only class that makes direct calls to an LDAP server.
 */
@Singleton
public class LdapDelegate implements DirectoryDelegate {

    /**
     * Private inner class for managing LDAP configuration details.
     */
    private class LdapConfig {

        /** The Constant PROPERTY_NAME. File containing necessary configurations for this class */
        public static final String PROPERTY_NAME = "/ldap.properties";

        /** The Constant ROLE_NONE. No access. */
        public static final String ROLE_NONE = "none";

        /** The Constant ROLE_ADMIN. (read/write/create) */
        public static final String ROLE_ADMIN = "admin";

        /** The Constant ROLE_SUPER_ADMIN. (read/write/create/manage) */
        public static final String ROLE_SUPER_ADMIN = "superadmin";

        /** The Constant ROLE_WRITER. (read/write) */
        public static final String ROLE_WRITER = "readwrite";

        /** The Constant ROLE_READER. (read only) */
        public static final String ROLE_READER = "readonly";

        /** The ldap host. */
        private String ldapHost;

        /** The ldap port. */
        private int ldapPort;
        
        /** The number of bCrypt rounds to apply to encrypted passwords. */
        private int bCryptRounds;

        /** Whether to secure connection. */
        private boolean secureConnection;

        /** The base Base Distinguished Name (e.g. dc=example,dc=com). */
        private String baseDN;

        /** The Wasabi Distinguished Name (e.g. cn=Wasabi,dc=example,dc=com) */
        private String wasabiDN;

        /** Type of entity used for login (e.g. uid) */
        private String loginEntity;

        /** Search key within Wasabi DN to attribute membership to a user (e.g. member) */
        private String membershipAttribute;

        /** Attribute key used to describe role (e.g. cn) */
        private String roleAttribute;

        /** The generic info DN for retrieving high level user details (e.g. name). */
        private String infoDN;

        /** The generic info DN password. */
        private String infoPassword;

        /** The Wasabi super admin group in LDAP. */
        private String superAdminGroup;

        /** The Wasabi admin group in LDAP. */
        private String adminGroup;

        /** The Wasabi reader group in LDAP. */
        private String readerGroup;

        /** The Wasabi writer group in LDAP. */
        private String writerGroup;

        /** The person email attribute in LDAP. */
        private String personEmailAttribute;

        /** The person first name attribute in LDAP. */
        private String personFirstNameAttribute;

        /** The person last name attribute in LDAP. */
        private String personLastNameAttribute;;

        /**
         * Instantiates a new ldap config.
         */
        protected LdapConfig() {
            Properties properties = create(PROPERTY_NAME, LdapDelegate.class);
            this.setLdapHost(getProperty("ldap.host", properties));
            this.setLdapPort(Integer.parseInt(getProperty("ldap.port", properties, "10389")));
            this.setSecureConnection(Boolean.parseBoolean(getProperty("ldap.secure", properties, "false")));
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
            this.setBCryptRounds(Integer.parseInt(getProperty("ldap.bcrypt.rounds", properties, "7")));
        }

        /**
         * Gets the admin group.
         *
         * @return the admin group
         */
        public String getAdminGroup() {
            return adminGroup;
        }

        /**
         * Gets the base DN.
         *
         * @return the base DN
         */
        public String getBaseDN() {
            return baseDN;
        }

        /**
         * Gets the info DN.
         *
         * @return the info DN
         */
        public String getInfoDN() {
            return infoDN;
        }

        /**
         * Gets the info password.
         *
         * @return the info password
         */
        public String getInfoPassword() {
            return infoPassword;
        }

        /**
         * Gets the ldap host.
         *
         * @return the ldap host
         */
        public String getLdapHost() {
            return ldapHost;
        }

        /**
         * Gets the ldap port.
         *
         * @return the ldap port
         */
        public int getLdapPort() {
            return ldapPort;
        }

        /**
         * Gets the login entity.
         *
         * @return the login entity
         */
        public String getLoginEntity() {
            return loginEntity;
        }

        /**
         * Gets the membership attribute.
         *
         * @return the membership attribute
         */
        public String getMembershipAttribute() {
            return membershipAttribute;
        }

        /**
         * Gets the person email attribute.
         *
         * @return the person email attribute
         */
        public String getPersonEmailAttribute() {
            return personEmailAttribute;
        }

        /**
         * Gets the person first name attribute.
         *
         * @return the person first name attribute
         */
        public String getPersonFirstNameAttribute() {
            return personFirstNameAttribute;
        }

        /**
         * Gets the person last name attribute.
         *
         * @return the person last name attribute
         */
        public String getPersonLastNameAttribute() {
            return personLastNameAttribute;
        }

        /**
         * Gets the reader group.
         *
         * @return the reader group
         */
        public String getReaderGroup() {
            return readerGroup;
        }

        /**
         * Gets the role attribute.
         *
         * @return the role attribute
         */
        public String getRoleAttribute() {
            return roleAttribute;
        }

        /**
         * Gets the role search attribute.
         *
         * @return the role search attribute
         */
        public String getRoleSearchAttribute() {
            return membershipAttribute + "=" + loginEntity + "=";
        }

        /**
         * Gets the super admin group.
         *
         * @return the super admin group
         */
        public String getSuperAdminGroup() {
            return superAdminGroup;
        }

        /**
         * Gets the wasabi DN.
         *
         * @return the wasabi DN
         */
        public String getWasabiDN() {
            return wasabiDN;
        }

        /**
         * Gets the writer group.
         *
         * @return the writer group
         */
        public String getWriterGroup() {
            return writerGroup;
        }

        /**
         * Checks if is secure connection.
         *
         * @return true, if is secure connection
         */
        public boolean isSecureConnection() {
            return secureConnection;
        }

        /**
         * Sets the admin group.
         *
         * @param adminGroup the new admin group
         */
        public void setAdminGroup(String adminGroup) {
            this.adminGroup = adminGroup;
        }

        /**
         * Sets the base DN.
         *
         * @param baseDN the new base DN
         */
        public void setBaseDN(String baseDN) {
            this.baseDN = baseDN;
        }

        /**
         * Sets the info DN.
         *
         * @param infoDN the new info DN
         */
        public void setInfoDN(String infoDN) {
            this.infoDN = infoDN;
        }

        /**
         * Sets the info password.
         *
         * @param infoPassword the new info password
         */
        public void setInfoPassword(String infoPassword) {
            this.infoPassword = infoPassword;
        }

        /**
         * Sets the ldap host.
         *
         * @param ldapHost the new ldap host
         */
        public void setLdapHost(String ldapHost) {
            this.ldapHost = ldapHost;
        }

        /**
         * Sets the ldap port.
         *
         * @param ldapPort the new ldap port
         */
        public void setLdapPort(int ldapPort) {
            this.ldapPort = ldapPort;
        }

        /**
         * Sets the login entity.
         *
         * @param loginEntity the new login entity
         */
        public void setLoginEntity(String loginEntity) {
            this.loginEntity = loginEntity;
        }

        /**
         * Sets the membership attribute.
         *
         * @param membershipAttribute the new membership attribute
         */
        public void setMembershipAttribute(String membershipAttribute) {
            this.membershipAttribute = membershipAttribute;
        }

        /**
         * Sets the person email attribute.
         *
         * @param personEmailAttribute the new person email attribute
         */
        public void setPersonEmailAttribute(String personEmailAttribute) {
            this.personEmailAttribute = personEmailAttribute;
        }

        /**
         * Sets the person first name attribute.
         *
         * @param personFirstNameAttribute the new person first name attribute
         */
        public void setPersonFirstNameAttribute(String personFirstNameAttribute) {
            this.personFirstNameAttribute = personFirstNameAttribute;
        }

        /**
         * Sets the person last name attribute.
         *
         * @param personLastNameAttribute the new person last name attribute
         */
        public void setPersonLastNameAttribute(String personLastNameAttribute) {
            this.personLastNameAttribute = personLastNameAttribute;
        }

        /**
         * Sets the reader group.
         *
         * @param readerGroup the new reader group
         */
        public void setReaderGroup(String readerGroup) {
            this.readerGroup = readerGroup;
        }

        /**
         * Sets the role attribute.
         *
         * @param roleAttribute the new role attribute
         */
        public void setRoleAttribute(String roleAttribute) {
            this.roleAttribute = roleAttribute;
        }

        /**
         * Sets the secure connection.
         *
         * @param secureConnection the new secure connection
         */
        public void setSecureConnection(boolean secureConnection) {
            this.secureConnection = secureConnection;
        }

        /**
         * Sets the super admin group.
         *
         * @param superAdminGroup the new super admin group
         */
        public void setSuperAdminGroup(String superAdminGroup) {
            this.superAdminGroup = superAdminGroup;
        }

        /**
         * Sets the wasabi DN.
         *
         * @param wasabiDN the new wasabi DN
         */
        public void setWasabiDN(String wasabiDN) {
            this.wasabiDN = wasabiDN;
        }

        /**
         * Sets the writer group.
         *
         * @param writerGroup the new writer group
         */
        public void setWriterGroup(String writerGroup) {
            this.writerGroup = writerGroup;
        }

        @Override
        public String toString() {
            return "LdapConfig [ldapHost=" + ldapHost + ", ldapPort=" + ldapPort + ", secureConnection="
                    + secureConnection + ", baseDN=" + baseDN + ", wasabiDN=" + wasabiDN + ", loginEntity="
                    + loginEntity + ", membershipAttribute=" + membershipAttribute + ", roleAttribute=" + roleAttribute
                    + ", infoDN=" + infoDN + ", infoPassword=[HIDDEN]" + ", superAdminGroup=" + superAdminGroup
                    + ", adminGroup=" + adminGroup + ", readerGroup=" + readerGroup + ", writerGroup=" + writerGroup
                    + ", personEmailAttribute=" + personEmailAttribute + ", personFirstNameAttribute="
                    + personFirstNameAttribute + ", personLastNameAttribute=" + personLastNameAttribute + "]";
        }

        /**
         * Translate role to expected Wasabi format
         *
         * @param providedRole the provided role from Ldap
         * @return the Wasabi role
         */
        public String translateRole(String providedRole) {
            if (providedRole == null) {
                return LdapConfig.ROLE_NONE;
            }
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

        public int getBCryptRounds() {
            return bCryptRounds;
        }

        public void setBCryptRounds(int bCryptRounds) {
            this.bCryptRounds = bCryptRounds;
        }
    }

    /** The cached search request for finding users. */
    private static SearchRequest userCacheSearchRequest;

    /** The Constant LOGGER. */
    private static final Logger LOGGER = getLogger(LdapDelegate.class);

    /** The config object. */
    private LdapConfig config;

    /**
     * Instantiates a new ldap delegate.
     */
    public LdapDelegate() {
        // Initialize the config
        this.config = new LdapConfig();
        LOGGER.debug("LdapDelegate created with {} ", this.config);
    }

    /**
     * Attempt to authenticate the user based on the given user credentials. This method will use the credentials as
     * part of the LDAP bind operation and if successful, retrieve the user details and role, cache them then return the
     * result.
     * 
     * @param userDirectory - The calling user directory
     * @param username - The target user
     * @param password - The target user password
     * @return directory user object
     * @throws AuthenticationException For all LDAP related connectivity issues and if the user/password combo was
     *             invalid
     */
    @Override
    public DirectoryUser authenticate(CachedUserDirectory userDirectory, String username, String password)
            throws AuthenticationException {
        try (LdapConnection connection = getLdapConnection()) {
            // Attempt to bind with the given credentials
            connection.bind(this.config.getLoginEntity() + "=" + username + "," + this.config.getBaseDN(), password);
            // If an LDAP connection was established, the username and password are valid
            if (connection.isConnected() && connection.isAuthenticated()) {
                // Use the connection to determine the user's Wasabi role
                String role = null;
                try (EntryCursor cursor = connection.search(this.config.getWasabiDN(),
                        "(" + this.config.getRoleSearchAttribute() + username + ")", SearchScope.ONELEVEL)) {
                    // Check the search results for the role attribute
                    for (Entry entry : cursor) {
                        Attribute attributeRole = entry.get(this.config.getRoleAttribute());
                        if (attributeRole != null) {
                            // Translate the role to expected Wasabi format
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    if (role == null || LdapConfig.ROLE_NONE.equals(role)) {
                        throw new AuthenticationException("User " + username + " does not have access to Wasabi.");
                    }
                }
                // Valid role, retrieve meta user details
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getLoginEntity() + "=" + username + ")", SearchScope.ONELEVEL)) {
                    DirectoryUser ldapUser = getDirectoryUserViaCursor(cursor);
                    if (ldapUser != null) {
                        ldapUser.setRole(role);
                        ldapUser.setPassword(encryptPassword(password));
                        userDirectory.addUserToCache(ldapUser);
                    }
                    return ldapUser;
                }
            }
        } catch (LdapAuthenticationException authException) {
            throw new AuthenticationException("LDAP Authentication failed for " + username);
        } catch (LdapException e) {
            LOGGER.debug("LDAP ERROR: Authentication failed with LdapException {}", e);
            throw new AuthenticationException("Error connecting to LDAP");
        } catch (IOException e) {
            LOGGER.debug(
                    "LDAP ERROR: Refresh cache search query failed with IOException: {} Verify your LDAP configuration",
                    e);
            throw new AuthenticationException("IOException exception connecting to LDAP");
        }
        return null;
    }

    /**
     * Retrieve the user details from LDAP for a given email. Note that this method does not retrieve/validate role
     * details nor does it cache the result.
     * 
     * @param userDirectory the calling userDirectory
     * @param email The target user email
     * @throws AuthenticationException For LDAP connectivity issues
     */
    @Override
    public DirectoryUser getDirectoryUserByEmail(CachedUserDirectory userDirectory, String email)
            throws AuthenticationException {
        // Use the info connection since we cannot authenticate the user
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                // We must use the base DN since the Wasabi dn is most likely not organized by email
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getPersonEmailAttribute() + "=" + email + ")", SearchScope.ONELEVEL)) {
                    // Because this method cannot verify role access by email and lookups by email are only
                    // performed for authorization assignments, this is intentionally not cached
                    return getDirectoryUserViaCursor(cursor);
                }
            }
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP: " + e.getMessage());
        } catch (IOException e) {
            throw new AuthenticationException("IO Exception connecting to LDAP: " + e.getMessage());
        }
        return null;
    }

    /**
     * Get user details from LDAP for a given user
     * 
     * @param userDirectory Calling user directory
     * @param username The target user
     * @return The user object
     * @throws AuthenticationException for any LDAP failures
     */
    @Override
    public DirectoryUser getDirectoryUserByUsername(CachedUserDirectory userDirectory, String username)
            throws AuthenticationException {
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                String role = null;
                // Since we have username, search the Wasabi dn
                try (EntryCursor cursor = connection.search(this.config.getWasabiDN(),
                        "(" + this.config.getRoleSearchAttribute() + username + ")", SearchScope.ONELEVEL)) {
                    for (Entry entry : cursor) {
                        Attribute attributeRole = entry.get(this.config.getRoleAttribute());
                        if (attributeRole != null) {
                            role = this.config.translateRole(attributeRole.getString());
                        }
                        break;
                    }
                    // If the user is not a Wasabi user, return immediately
                    if (role == null || LdapConfig.ROLE_NONE.equals(role)) {
                        return null;
                    }
                }
                // Valid wasabi user, retrieve meta user details
                try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                        "(" + this.config.getLoginEntity() + "=" + username + ")", SearchScope.ONELEVEL)) {
                    DirectoryUser DirectoryUser = getDirectoryUserViaCursor(cursor);
                    // Cache the result in the user directory
                    if (DirectoryUser != null) {
                        DirectoryUser.setRole(role);
                        userDirectory.addUserToCache(DirectoryUser);
                        return DirectoryUser;
                    }
                }
            }
        } catch (LdapAuthenticationException authException) {
            throw new AuthenticationException("LDAP Authentication failed");
        } catch (LdapException e) {
            throw new AuthenticationException("Error connecting to LDAP: " + e.getMessage());
        } catch (IOException e) {
            throw new AuthenticationException("Error connecting to LDAP.");
        }
        return null;
    }

    /**
     * Validate a directory token
     * 
     * @param userDirectory - the calling user directory
     * @param username - The username to validate
     * @param encodedPassword - The encrypted password to validate
     * @return Always returns whether the token is valid or not
     */
    @Override
    public boolean isDirectoryTokenValid(CachedUserDirectory userDirectory, String username, String encodedPassword) {
        try {
            DirectoryUser userInfo = userDirectory.lookupDirectoryUser(username);
            // It is possible for the password to be null if it was retrieved outside of the login flow
            if (userInfo != null && userInfo.getPassword() != null) {
                // Encoded passwords are only in the cache
                return userInfo.getPassword().equals(encodedPassword);
            }
        } catch (AuthenticationException ae) {
            return false;
        }
        return false;
    }

    /**
     * Populates the user cache with all Wasabi users
     * 
     * @param The calling CachedUserDirectory instance
     * @throws AuthenticationException If unable to connect to ldap or bad LDAP queries
     */
    @Override
    public void populateUserCache(CachedUserDirectory userDirectory) throws AuthenticationException {
        try (LdapConnection connection = getLdapInfoConnection()) {
            if (connection.isConnected() && connection.isAuthenticated()) {
                // Search the Wasabi DN for all objects
                try (SearchCursor searchCursor = connection.search(getUserCacheSearchRequest())) {
                    while (searchCursor.next()) {
                        Response response = searchCursor.get();
                        // process the SearchResultEntry
                        if (response instanceof SearchResultEntry) {
                            Entry resultEntry = ((SearchResultEntry) response).getEntry();
                            iterateGroupMembersForCache(connection, userDirectory, resultEntry);
                        }
                    }
                }
            }
        } catch (CursorException e) {
            LOGGER.error(
                    "LDAP FATAL ERROR: Refresh cache search query failed with CursorException: Verify your LDAP configuration",
                    e);
            throw new AuthenticationException("LDAP Search Query Failed: " + e.getMessage());
        } catch (LdapAuthenticationException authException) {
            LOGGER.error(
                    "LDAP FATAL ERROR: Unable to refresh cache. Check your ldap.dn.info properties and ensure appropriate access. All LDAP functionality will fail. {}",
                    authException);
            ;
            throw new AuthenticationException("LDAP Authentication Failed: " + authException.getMessage());
        } catch (LdapException e) {
            LOGGER.error(
                    "LDAP FATAL ERROR: Refresh cache search query failed with LdapException: Verify your LDAP configuration",
                    e);
            throw new AuthenticationException("Error connecting to LDAP: " + e.getMessage());
        } catch (IOException e) {
            LOGGER.error(
                    "LDAP FATAL ERROR: Refresh cache search query failed with IOException: Verify your LDAP configuration",
                    e);
            throw new AuthenticationException("IOException exception connecting to LDAP: " + e.getMessage());
        }
    }

    /**
     * Encrypt a clear text password
     *
     * @param password the clear text password
     * @return the string representation of the encrypted password
     */
    private String encryptPassword(String password) {
        return BCrypt.hashPw(password, BCrypt.gensalt(this.config.getBCryptRounds()));
    }

    /**
     * Utility function to cache resulting user of group membership query
     * 
     * @param connection Open connection to the LDAP server (for reuse)
     * @param userDirectory The cached user directory to add the user to
     * @param role Previously retrieved role (based on group membership)
     * @param userDn The user's DN
     * @throws LdapException For any LDAP failures
     * @throws IOException For any cache storage related failures
     */
    protected void addDirectoryUserToCache(LdapConnection connection, CachedUserDirectory userDirectory, String role,
            String userDn) throws LdapException, IOException {
        // Build a cursor to retrieve meta user details
        try (EntryCursor cursor = connection.search(this.config.getBaseDN(),
                "(" + this.config.getLoginEntity() + "=" + userDn + ")", SearchScope.ONELEVEL)) {
            DirectoryUser user = getDirectoryUserViaCursor(cursor);
            // Set the role for the user based on the current group
            if (user != null) {
                user.setRole(role);
                // Cache the result
                userDirectory.addUserToCache(user);
            }
        }
    }

    /**
     * Convenience method that builds the directory user object via a search cursor for the user details.
     *
     * @param cursor The search cursor for the user details
     * @return the directory user
     * @throws LdapInvalidAttributeValueException For invalid attribute mappings
     * @throws AuthenticationException If there is not a login entity as this is the primary key
     */
    protected DirectoryUser getDirectoryUserViaCursor(EntryCursor cursor)
            throws LdapInvalidAttributeValueException, AuthenticationException {
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

    /**
     * Gets the ldap connection.
     * 
     * @return the ldap connection
     */
    protected LdapConnection getLdapConnection() {
        return new LdapNetworkConnection(this.config.getLdapHost(), this.config.getLdapPort(),
                this.config.isSecureConnection());
    }

    /**
     * Gets a generic LDAP info connection
     *
     * @return the ldap info connection
     * @throws LdapException the ldap exception
     */
    protected LdapConnection getLdapInfoConnection() throws LdapException {
        LdapConnection connection = getLdapConnection();
        connection.bind(this.config.getInfoDN(), this.config.getInfoPassword());
        return connection;
    }

    /**
     * Gets the cached user search request (and builds it if necessary).
     *
     * @return the user cache search request
     * @throws LdapException If there are DN validation errors or invalid filters
     */
    protected SearchRequest getUserCacheSearchRequest() throws LdapException {
        // This should never be null unless it is the first request
        if (userCacheSearchRequest == null) {
            // In unlikely event multiple threads reach this point, lock initialization
            synchronized (this) {
                SearchRequest searchRequest = new SearchRequestImpl();
                searchRequest.setScope(SearchScope.SUBTREE);
                searchRequest.addAttributes(this.config.getRoleAttribute());
                searchRequest.addAttributes(this.config.getMembershipAttribute());
                // Max of 5 minutes (in seconds)
                searchRequest.setTimeLimit(60 * 5);
                searchRequest.setBase(new Dn(this.config.getWasabiDN()));
                searchRequest.setFilter("(objectclass=*)");
                userCacheSearchRequest = searchRequest;
            }
        }
        return userCacheSearchRequest;
    }

    /**
     * Utility method for iterating a group result for each member
     * 
     * @param connection Open connection to the LDAP server (for reuse)
     * @param userDirectory The cached user directory to add the user to
     * @param resultEntry The LDAP result cursor for the group
     * @throws LdapException For any LDAP failures
     * @throws IOException For any cache storage related failures
     */
    protected void iterateGroupMembersForCache(LdapConnection connection, CachedUserDirectory userDirectory,
            Entry resultEntry) throws LdapException, IOException {
        Attribute group = resultEntry.get(this.config.getRoleAttribute());
        // Group determines role
        if (group == null || LdapConfig.ROLE_NONE.equals(this.config.translateRole(group.getString()))) {
            // It is possible there are non-Role related groups in the same Wasabi DN - this prevents
            // unnecessary processing of these groups or class objects
            return;
        }
        // All members of this group have the same role, store the Wasabi role for reuse in user building
        String role = this.config.translateRole(group.getString());
        // Obtain an iterator of members
        Attribute memberAttribute = resultEntry.get(this.config.getMembershipAttribute());
        Iterator<Value<?>> members = memberAttribute.iterator();
        while (members.hasNext()) {
            String member = members.next().getString();
            // Membership is generally uid=username, remove the first part to get only the username
            if (member.contains("=")) {
                member = member.substring(member.indexOf("=") + 1);
            }
            addDirectoryUserToCache(connection, userDirectory, role, member);
        }
    }
}
