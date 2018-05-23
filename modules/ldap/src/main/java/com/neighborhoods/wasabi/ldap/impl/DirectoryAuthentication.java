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

import static com.google.common.base.Optional.fromNullable;
import static com.intuit.wasabi.authenticationobjects.LoginToken.withAccessToken;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.slf4j.LoggerFactory.getLogger;

import org.slf4j.Logger;

import com.google.common.base.Optional;
import com.google.inject.Inject;
import com.intuit.wasabi.authentication.Authentication;
import com.intuit.wasabi.authenticationobjects.LoginToken;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.neighborhoods.wasabi.ldap.CachedUserDirectory;

/**
 * The Class DirectoryAuthentication.
 * 
 * This implements the Authentication interface and delegates all Authentication business logic to the
 * CachedUserDirectory interface.
 * 
 * Primary purpose is to process front-end login attempts and validate authentication tokens after the user has logged
 * in.
 */
public class DirectoryAuthentication implements Authentication {

    /** The Constant SPACE. */
    private static final String SPACE = " ";

    /** The Constant SEMICOLON. */
    private static final String COLON = ":";

    /** The Constant BASIC. */
    public static final String BASIC = "Basic";

    /** The Constant EMPTY. */
    public static final String EMPTY = "";

    /** The Constant LOGGER. */
    private static final Logger LOGGER = getLogger(DirectoryAuthentication.class);

    /** The user directory. */
    private final CachedUserDirectory userDirectory;

    /**
     * Instantiates a new directory authentication.
     *
     * @param userDirectory the user directory
     */
    @Inject
    public DirectoryAuthentication(CachedUserDirectory userDirectory) {
        this.userDirectory = userDirectory;
    }

    /**
     * Check whether a user exists
     *
     * @param userEmail the user's email
     * @return the UserInfo object of the requested user
     * @throws AuthenticationException if the user does not exist
     */
    @Override
    public UserInfo getUserExists(final String userEmail) {
        LOGGER.debug("Authentication token received as: {}", userEmail);

        if (isBlank(userEmail)) {
            throw new AuthenticationException("userEmail is blank");
        }
        return userDirectory.lookupUserByEmail(userEmail);
    }

    /**
     * Attempts to return the LoginToken of the user as if it was obtained via HTTP Basic authentication.
     *
     * @param authHeader the authentication header
     * @return a login token for this user (always)
     * @throws AuthenticationException for failed login attempts
     */
    @Override
    public LoginToken logIn(final String authHeader) {
        DirectoryUserCredential credential = parseUsernamePassword(fromNullable(authHeader));
        DirectoryUser user = userDirectory.authenticate(credential.username, credential.password);
        if (user == null) {
            throw new AuthenticationException("Authentication login failed. Invalid Login Credential");
        }
        // Get the username from the username object and the encoded password for persistence in the access token
        DirectoryUserCredential encodedCredentials = new DirectoryUserCredential(user.getUsername().getUsername(),
                user.getPassword());
        return withAccessToken(encodedCredentials.toBase64Encode()).withTokenType(BASIC).build();
    }

    /**
     * Process a logout request
     * 
     * @param tokenHeader the token header
     * @return success flag for logging out
     */
    @Override
    public boolean logOut(final String tokenHeader) {
        DirectoryUserCredential credential = parseUsernamePassword(fromNullable(tokenHeader));
        userDirectory.removeUserFromCache(credential.username);
        return true;
    }

    /**
     * Parses the username password.
     *
     * @param authHeader The http authroization header
     * @return DirectoryUserCredential for the authHeader
     * @throws AuthenticationException for invalid headers
     */
    protected static DirectoryUserCredential parseUsernamePassword(final Optional<String> authHeader) {
        if (!authHeader.isPresent()) {
            throw new AuthenticationException("Null Authentication Header is not supported");
        }

        if (!authHeader.or(SPACE).contains(BASIC)) {
            throw new AuthenticationException("Only Basic Authentication is supported");
        }

        final String encodedUserPassword = authHeader.get().substring(authHeader.get().lastIndexOf(SPACE));
        String usernameAndPassword;

        try {
            usernameAndPassword = new String(decodeBase64(encodedUserPassword.getBytes()));
        } catch (Exception e) {
            throw new AuthenticationException("error parsing username and password", e);
        }

        // Core Wasabi doesn't allow : in both usernames and passwords. This will allow passwords to contain any number
        // of : but usernames will remain an issue
        String[] fields = usernameAndPassword.split(COLON, 2);

        if (fields.length < 2) {
            throw new AuthenticationException("Username or password are empty.");
        }

        if (isBlank(fields[0]) || isBlank(fields[1])) {
            throw new AuthenticationException("Username or password are empty.");
        }

        return new DirectoryUserCredential(fields[0], fields[1]);
    }

    /**
     * Attempts to verify the user token retrieved via the {@link #logIn(String) logIn} method.
     *
     * @param tokenHeader the token header
     * @return a login token for this user (always)
     * @throws AuthenticationException for invalid tokens
     */
    @Override
    public LoginToken verifyToken(final String tokenHeader) {
        LOGGER.debug("Authentication token received as: {}", tokenHeader);

        DirectoryUserCredential credential = parseUsernamePassword(fromNullable(tokenHeader));

        if (userDirectory.isDirectoryTokenValid(credential.username, credential.password)) {
            return withAccessToken(credential.toBase64Encode()).withTokenType(BASIC).build();
        }
        throw new AuthenticationException("Authentication token is not valid");
    }
}
