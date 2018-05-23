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

import static com.intuit.wasabi.authorizationobjects.Permission.SUPERADMIN;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import com.datastax.driver.mapping.Result;
import com.google.common.base.Optional;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.authorization.Authorization;
import com.intuit.wasabi.authorizationobjects.Permission;
import com.intuit.wasabi.authorizationobjects.Role;
import com.intuit.wasabi.authorizationobjects.UserPermissions;
import com.intuit.wasabi.authorizationobjects.UserPermissionsList;
import com.intuit.wasabi.authorizationobjects.UserRole;
import com.intuit.wasabi.authorizationobjects.UserRoleList;
import com.intuit.wasabi.eventlog.EventLog;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.experimentobjects.Application;
import com.intuit.wasabi.repository.cassandra.accessor.ApplicationListAccessor;
import com.intuit.wasabi.repository.cassandra.pojo.ApplicationList;
import com.neighborhoods.wasabi.ldap.CachedUserDirectory;

/**
 * The Class DirectoryAuthorization.
 * 
 * Primary purpose is to handle authorization requests for actions (e.g. read/write). This class delegates all role
 * related retrieval operations to the CachedUserDirectory.
 * 
 * Note that due to core Wasabi UI limitations, application/experiment based authorization have been collapsed. Meaning
 * a reader will have access to all applications. Unsupported operations could not be removed from the UI so an
 * appropriate exception is thrown and displayed to users in the event they attempt to modify ACLs or perform other role
 * based assignments.
 */
public class DirectoryAuthorization implements Authorization {

    /** The Constant DIRECTORY_OPERATION_NOT_SUPPORTED. Displayed as message to user for unsupported actions */
    private static final String DIRECTORY_OPERATION_NOT_SUPPORTED = "Roles are managed via LDAP. Contact your administrator for assistance.";

    /**
     * The Constant DIRECTORY_CACHE_USER. This is a simulated user to add the ability to clear the UserDirectoryCache
     * from the front end.
     */
    private static final String DIRECTORY_CACHE_USER = "user_directory_cache";

    /** The Constant SUPERADMIN_PERMISSIONS. Container for holding SuperAdmin permissions list */
    private static final List<Permission> SUPERADMIN_PERMISSIONS = new ArrayList<>();

    /** The Constant SPACE. */
    private static final String SPACE = " ";

    /** The Constant BASIC. */
    private static final CharSequence BASIC = "Basic";

    /** The Constant WILDCARD. */
    private static final Application.Name WILDCARD = Application.Name.valueOf("wildcard");

    /** The Constant COLON. */
    private static final String COLON = ":";

    /** The Constant LOGGER. */
    private static final Logger LOGGER = getLogger(DirectoryAuthorization.class);

    static {
        SUPERADMIN_PERMISSIONS.add(SUPERADMIN);
    }

    /** The event log. */
    private final EventLog eventLog;

    /** The user directory. */
    private final CachedUserDirectory userDirectory;

    /** The application list accessor. */
    private final ApplicationListAccessor applicationListAccessor;

    /**
     * Instantiates a new directory authorization instance.
     *
     * @param applicationListAccessor the application list accessor
     * @param eventLog the event log
     * @param userDirectory the user directory
     */
    @Inject
    public DirectoryAuthorization(ApplicationListAccessor applicationListAccessor, final EventLog eventLog,
            final CachedUserDirectory userDirectory) {
        super();
        this.eventLog = eventLog;
        this.userDirectory = userDirectory;
        this.applicationListAccessor = applicationListAccessor;
    }

    /**
     * Set a user to super admin role
     * 
     * @throws UnsupportedOperationException for all calls to this method
     */
    @Override
    public void assignUserToSuperAdminRole(final UserInfo candidateUserInfo, final UserInfo assigningUserInfo) {
        throw new UnsupportedOperationException(DIRECTORY_OPERATION_NOT_SUPPORTED);
    }

    /**
     * Validate the given user is a super admin. Note that unauthorized access attempts will cause the user to be force
     * logged out.
     * 
     * @param userID the target user
     * @throws AuthenticationException when the user is not a superadmin
     */
    @Override
    public void checkSuperAdmin(UserInfo.Username userID) {
        DirectoryUser user = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (!Role.toRole(user.getRole()).equals(Role.SUPERADMIN)) {
            throw new AuthenticationException("user " + userID + " is not a superadmin");
        }
    }

    /**
     * Validate user has permission for the given application
     * 
     * @param userID the user ID
     * @param applicationName the target application
     * @throws AuthenticationException for unauthorized access
     */
    @Override
    public void checkUserPermissions(UserInfo.Username userID, Application.Name applicationName,
            Permission permission) {
        // get the user's permissions for this applicationName
        UserPermissions userPermissions = getUserPermissions(userID, applicationName);
        // check that the user is permitted to perform the action
        if (userPermissions == null || !userPermissions.getPermissions().contains(permission)) {
            throw new AuthenticationException("user " + userID + " is not authorized to " + permission.toString()
                    + " on application " + applicationName.toString());
        }
    }

    /**
     * Delete a user role. This is a NO-OP via Wasabi. All user management must be performed directly within LDAP.
     * 
     * @throws UnsupportedOperationException for all calls to this method
     */
    @Override
    public void deleteUserRole(UserInfo.Username userID, Application.Name applicationName, UserInfo admin) {
        throw new UnsupportedOperationException(DIRECTORY_OPERATION_NOT_SUPPORTED);
    }

    /**
     * Gets all application names from the application list.
     *
     * @return list of all application names
     */
    List<String> getAllApplicationNamesFromApplicationList() {
        Result<ApplicationList> allAppNames = applicationListAccessor.getUniqueAppName();
        return StreamSupport
                .stream(Spliterators.spliteratorUnknownSize(allAppNames.iterator(), Spliterator.ORDERED), false)
                .map(t -> t.getAppName()).collect(Collectors.toList());
    }

    /**
     * Retrieve all users of the application. Note that all application based permissions have been collapsed.
     * 
     * @param applicationName the application name
     * @return collection of user/role pairings for the application
     */
    @Override
    public UserRoleList getApplicationUsers(Application.Name applicationName) {
        UserRoleList userRoleList = new UserRoleList();
        this.userDirectory.getAllUsers().forEach(user -> {
            // Translate the role to the wrapper object
            Role role = Role.toRole(user.getRole());
            // Build a UserRole instance based on the directory result
            userRoleList.addRole(UserRole.newInstance(applicationName, role).withUserID(user.getUsername())
                    .withUserEmail(user.getEmail()).withFirstName(user.getFirstName()).withLastName(user.getLastName())
                    .build());
        });
        return userRoleList;
    }

    /**
     * Return the permission list based on role
     * 
     * @param role The role
     * @return role permissions
     */
    @Override
    public List<Permission> getPermissionsFromRole(Role role) {
        return role.getRolePermissions();
    }

    /**
     * Retrieve all super admins
     * 
     * @return the collection of all user/role pairings containing only superadmins
     */
    @Override
    public List<UserRole> getSuperAdminRoleList() {
        List<UserRole> userRoleList = new ArrayList<UserRole>();
        // Filter all users based on role
        this.userDirectory.getAllUsers().filter(user -> {
            Role role = Role.toRole(user.getRole());
            return Role.SUPERADMIN.equals(role);
        }).forEach(superAdmin -> {
            // For each result (superadmin) translate/build the wrapper object
            userRoleList.add(UserRole.newInstance(WILDCARD, Role.toRole(superAdmin.getRole()))
                    .withUserID(superAdmin.getUsername()).withUserEmail(superAdmin.getEmail())
                    .withFirstName(superAdmin.getFirstName()).withLastName(superAdmin.getLastName()).build());
        });
        // Append the directory cache user so it can appear in the UI list (used for clearing the cache)
        userRoleList.add(UserRole.newInstance(WILDCARD, Role.SUPERADMIN)
                .withUserID(UserInfo.Username.valueOf(DIRECTORY_CACHE_USER))
                .withUserEmail(DIRECTORY_CACHE_USER + "@LDAP").withFirstName("User").withLastName("Cache").build());
        return userRoleList;
    }

    /**
     * Retrieve the username based on the authorization header
     * 
     * @param authHeader authorization header
     * @return the parsed username
     */
    @Override
    public UserInfo.Username getUser(String authHeader) {
        return parseUsername(Optional.fromNullable(authHeader));
    }

    /**
     * Retrieve user meta-details
     * 
     * @param userID the target user
     * @return Encapsulated user details
     */
    @Override
    public UserInfo getUserInfo(UserInfo.Username userID) {
        UserInfo result;
        if (userID != null && !StringUtils.isBlank(userID.toString())) {
            result = this.userDirectory.lookupUser(userID);
            // If the user is our "fake" directory cache, return the details manually
            if (result == null && DIRECTORY_CACHE_USER.equals(userID.getUsername())) {
                result = new UserInfo.Builder(UserInfo.Username.valueOf(DIRECTORY_CACHE_USER))
                        .withUserId(DIRECTORY_CACHE_USER).build();
            }
        } else {
            throw new AuthenticationException("The user name was null or empty for retrieving the UserInfo.");
        }
        return result;
    }

    /**
     * Retrieve the user permissions for a given user and application
     * 
     * @param userID the username of the target user
     * @param applicationName the targeted application name
     * @return collection of user permissions for the given parameters
     */
    @Override
    public UserPermissions getUserPermissions(UserInfo.Username userID, Application.Name applicationName) {
        UserPermissions result = null;
        DirectoryUser user = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (user != null && user.getRole() != null) {
            // Translate to the wrapper object
            result = UserPermissions.newInstance(applicationName, Role.toRole(user.getRole()).getRolePermissions())
                    .build();
        }
        return result;
    }

    /**
     * Retrieve the permission list object for a given user
     * 
     * @param userID the username of the target user
     * @return container of permissions for the user
     */
    @Override
    public UserPermissionsList getUserPermissionsList(UserInfo.Username userID) {
        UserPermissionsList userPermissionsList = new UserPermissionsList();
        DirectoryUser userInfo = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (userInfo != null) {
            // For directory services, roles have been collapsed so retrieve all applications
            List<String> allAppNames = getAllApplicationNamesFromApplicationList();
            // Translate each application in the stream to the wrapper object using the user entity
            allAppNames.stream()
                    .map(app -> UserPermissions.newInstance(Application.Name.valueOf(app),
                            Role.toRole(userInfo.getRole()).getRolePermissions()).build())
                    .forEach(userPermissionsList::addPermissions);
        }
        return userPermissionsList;
    }

    /**
     * Get all application access/roles for a given user
     * 
     * @param userID the targeted user
     * @return a collection of the user's roles for each application
     */
    @Override
    public UserRoleList getUserRoleList(UserInfo.Username userID) {
        UserRoleList userRoleList = new UserRoleList();
        DirectoryUser userInfo = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (userInfo != null) {
            // For directory services, roles have been collapsed so retrieve all applications
            List<String> allAppNames = getAllApplicationNamesFromApplicationList();
            // Translate each application in the stream to the wrapper object using the user entity
            allAppNames.stream()
                    .forEach(app -> UserRole.newInstance(Application.Name.valueOf(app), Role.toRole(userInfo.getRole()))
                            .withUserID(userID).withUserEmail(userInfo.getEmail())
                            .withFirstName(userInfo.getFirstName()).withLastName(userInfo.getLastName()).build());
        }
        return userRoleList;
    }

    /**
     * Parses the username from auth headers
     *
     * @param authHeader the auth header
     * @return the user's username
     * @throws AuthenticationException for bad auth headers
     */
    private UserInfo.Username parseUsername(Optional<String> authHeader) {
        DirectoryUserCredential credential = DirectoryAuthentication.parseUsernamePassword(authHeader);
        return UserInfo.from(Username.valueOf(credential.username)).build().getUsername();
    }

    /**
     * Remove a user from super admin role
     * 
     * @throws UnsupportedOperationException for all calls to this method
     */
    @Override
    public void removeUserFromSuperAdminRole(final UserInfo candidateUserInfo, final UserInfo assigningUserInfo) {
        // If the requested delete operation is the "fake" user cache
        if (DIRECTORY_CACHE_USER.equals(candidateUserInfo.getUsername().getUsername())) {
            // Then perform a refresh of the cache
            this.userDirectory.refreshCache();
            // And report the result to the user (this exception is our only way to inject messages into the UI)
            throw new UnsupportedOperationException("Cache refresh completed");
        }
        // Otherwise, the operation is not supported
        throw new UnsupportedOperationException(DIRECTORY_OPERATION_NOT_SUPPORTED);
    }

    /**
     * Set a user role
     * 
     * @throws UnsupportedOperationException for all calls to this method
     */
    @Override
    public Map setUserRole(UserRole userRole, UserInfo admin) {
        /**
         * When admin is null, it is most likely coming from the Experiment creation page. Allow
         * this to proceed to avoid confusion, but this is a NOOP.
         * @see com.intuit.wasabi.api.ExperimentsResource.putExperiment()
         */
        if(admin==null) {
            Map<String, String> status = new HashMap<>();
            status.put("applicationName", userRole.getApplicationName().toString());
            status.put("userID", userRole.getUserID().toString());
            status.put("role", userRole.getRole().toString());
            status.put("roleAssignmentStatus", "SUCCESS");
            return status;
        }
        throw new UnsupportedOperationException(DIRECTORY_OPERATION_NOT_SUPPORTED);
    }

}
