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

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
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
import com.intuit.wasabi.eventlog.events.AuthorizationChangeEvent;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.experiment.Experiments;
import com.intuit.wasabi.experimentobjects.Application;
import com.intuit.wasabi.experimentobjects.Experiment;
import com.intuit.wasabi.repository.AuthorizationRepository;
import com.intuit.wasabi.repository.RepositoryException;
import com.intuit.wasabi.repository.cassandra.accessor.ApplicationListAccessor;
import com.intuit.wasabi.repository.cassandra.pojo.AppRole;
import com.intuit.wasabi.repository.cassandra.pojo.ApplicationList;
import com.datastax.driver.mapping.Result;
import com.nhds.wasabi.ldap.impl.DirectoryUser;
import com.nhds.wasabi.ldap.impl.LdapUserDirectory;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static com.intuit.wasabi.authorizationobjects.Permission.SUPERADMIN;
import static org.slf4j.LoggerFactory.getLogger;

public class DirectoryAuthorization implements Authorization {
    private static final String LDAP_OPERATION_NOT_SUPPORTED = "Roles are managed via LDAP. Contact your administrator for assistance.";
    private static final String LDAP_USER_CACHE_USERNAME = "ldap_user_cache";
    private static final List<Permission> SUPERADMIN_PERMISSIONS = new ArrayList<>();
    private static final String SPACE = " ";
    private static final CharSequence BASIC = "Basic";
    private static final Application.Name WILDCARD = Application.Name.valueOf("wildcard");
    private static final String COLON = ":";
    private static final Logger LOGGER = getLogger(DirectoryAuthorization.class);

    static {
        SUPERADMIN_PERMISSIONS.add(SUPERADMIN);
    }

    private final AuthorizationRepository authorizationRepository;
    private final Experiments experiments;
    private final EventLog eventLog;
    private final LdapUserDirectory userDirectory;
    private final ApplicationListAccessor applicationListAccessor;

    @Inject
    public DirectoryAuthorization(ApplicationListAccessor applicationListAccessor,
            final AuthorizationRepository authorizationRepository, final Experiments experiments,
            final EventLog eventLog, final LdapUserDirectory userDirectory) {
        super();

        this.authorizationRepository = authorizationRepository;
        this.experiments = experiments;
        this.eventLog = eventLog;
        this.userDirectory = userDirectory;
        this.applicationListAccessor = applicationListAccessor;
    }

    @Override
    public List<Permission> getPermissionsFromRole(Role role) {
        return role.getRolePermissions();
    }

    List<String> getAllApplicationNameFromApplicationList() {
        Result<ApplicationList> allAppNames = applicationListAccessor.getUniqueAppName();
        return StreamSupport
                .stream(Spliterators.spliteratorUnknownSize(allAppNames.iterator(), Spliterator.ORDERED), false)
                .map(t -> t.getAppName()).collect(Collectors.toList());
    }

    @Override
    public UserPermissionsList getUserPermissionsList(UserInfo.Username userID) {
        UserPermissionsList userPermissionsList = new UserPermissionsList();
        DirectoryUser userInfo = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (userInfo != null) {
            List<String> allAppNames = getAllApplicationNameFromApplicationList();

            allAppNames.stream()
                    .map(t -> UserPermissions.newInstance(Application.Name.valueOf(t),
                            Role.toRole(userInfo.getRole()).getRolePermissions()).build())
                    .forEach(userPermissionsList::addPermissions);
        }
        return userPermissionsList;
    }

    @Override
    public UserRoleList getApplicationUsers(Application.Name applicationName) {
        // return authorizationRepository.getApplicationUsers(applicationName);
        UserRoleList userRoleList = new UserRoleList();
        this.userDirectory.getAllUsers().forEach(user -> {
            Role role = Role.toRole(user.getRole());
            userRoleList.addRole(UserRole.newInstance(applicationName, role).withUserID(user.getUsername())
                    .withUserEmail(user.getEmail()).withFirstName(user.getFirstName()).withLastName(user.getLastName())
                    .build());
        });
        ;

        /*
         * HashMap<String, LdapUser> allUsers = this.userDirectory.getUsers(); Iterator<LdapUser> users =
         * allUsers.values().iterator(); while (users.hasNext()) { LdapUser user = users.next(); Role role =
         * Role.toRole(user.getRole()); userRoleList.addRole(UserRole.newInstance(applicationName,
         * role).withUserID(user.getUsername())
         * .withUserEmail(user.getEmail()).withFirstName(user.getFirstName()).withLastName(user.getLastName())
         * .build()); }
         */
        return userRoleList;
    }

    @Override
    public UserPermissions getUserPermissions(UserInfo.Username userID, Application.Name applicationName) {
        UserPermissions result = null;
        DirectoryUser user = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (user != null && user.getRole() != null) {
            result = UserPermissions.newInstance(applicationName, Role.toRole(user.getRole()).getRolePermissions())
                    .build();
        }
        return result;
    }

    @Override
    public void deleteUserRole(UserInfo.Username userID, Application.Name applicationName, UserInfo admin) {
        throw new UnsupportedOperationException(LDAP_OPERATION_NOT_SUPPORTED);
    }

    @Override
    public void checkUserPermissions(UserInfo.Username userID, Application.Name applicationName,
            Permission permission) {
        // get the user's permissions for this applicationName
        UserPermissions userPermissions = getUserPermissions(userID, applicationName);
        // check that the user is permitted to perform the action
        if (userPermissions == null || !userPermissions.getPermissions().contains(permission)) {
            throw new AuthenticationException("error, user " + userID + " not authorized to " + permission.toString()
                    + " on application " + applicationName.toString());
        }
    }

    // TODO: move this to authentication instead of authorization
    @Override
    public UserInfo.Username getUser(String authHeader) {
        return parseUsername(Optional.fromNullable(authHeader));
    }

    @Override
    public Map setUserRole(UserRole userRole, UserInfo admin) {
        throw new UnsupportedOperationException(LDAP_OPERATION_NOT_SUPPORTED);
    }

    @Override
    public UserRoleList getUserRoleList(UserInfo.Username userID) {
        // return authorizationRepository.getUserRoleList(userID);
        UserRoleList userRoleList = new UserRoleList();
        DirectoryUser userInfo = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (userInfo != null) {
            List<String> allAppNames = getAllApplicationNameFromApplicationList();
            Iterator<String> apps = allAppNames.iterator();
            while (apps.hasNext()) {
                userRoleList.addRole(
                        UserRole.newInstance(Application.Name.valueOf(apps.next()), Role.toRole(userInfo.getRole()))
                                .withUserID(userID).withUserEmail(userInfo.getEmail())
                                .withFirstName(userInfo.getFirstName()).withLastName(userInfo.getLastName()).build());
            }
        }
        return userRoleList;
    }

    @Override
    public void checkSuperAdmin(UserInfo.Username userID) {
        DirectoryUser user = this.userDirectory.lookupDirectoryUser(userID.getUsername());
        if (!Role.toRole(user.getRole()).equals(Role.SUPERADMIN)) {
            throw new AuthenticationException("error, user " + userID + " is not a superadmin");
        }
    }

    @Override
    public UserInfo getUserInfo(UserInfo.Username userID) {
        UserInfo result;
        if (userID != null && !StringUtils.isBlank(userID.toString())) {
            result = this.userDirectory.lookupUser(userID);
            if (result == null && LDAP_USER_CACHE_USERNAME.equals(userID.getUsername())) {
                result = new UserInfo.Builder(UserInfo.Username.valueOf(LDAP_USER_CACHE_USERNAME))
                        .withUserId(LDAP_USER_CACHE_USERNAME).build();
            }
        } else {
            throw new AuthenticationException("The user name was null or empty for retrieving the UserInfo.");
        }
        return result;
    }

    private UserInfo.Username parseUsername(Optional<String> authHeader) {
        if (!authHeader.isPresent()) {
            throw new AuthenticationException("Null Authentication Header is not supported");
        }

        if (!authHeader.or(SPACE).contains(BASIC)) {
            throw new AuthenticationException("Only Basic Authentication is supported");
        }

        final String encodedUserPassword = authHeader.get().substring(authHeader.get().lastIndexOf(SPACE));
        LOGGER.trace("Base64 decoded username and password is: {}", encodedUserPassword);
        String usernameAndPassword;
        try {
            usernameAndPassword = new String(Base64.decodeBase64(encodedUserPassword.getBytes()));
        } catch (Exception e) {
            throw new AuthenticationException("error parsing username and password", e);
        }

        // Split username and password tokens
        String[] fields = usernameAndPassword.split(COLON);

        if (fields.length > 2) {
            throw new AuthenticationException("More than one username and password provided, or one contains ':'");
        } else if (fields.length < 2) {
            throw new AuthenticationException("Username or password are empty.");
        }

        if (StringUtils.isBlank(fields[0]) || StringUtils.isBlank(fields[1])) {
            throw new AuthenticationException("Username or password are empty.");
        }

        return UserInfo.Username.valueOf(fields[0]);
    }

    @Override
    public void assignUserToSuperAdminRole(final UserInfo candidateUserInfo, final UserInfo assigningUserInfo) {
        throw new UnsupportedOperationException(LDAP_OPERATION_NOT_SUPPORTED);
    }

    @Override
    public void removeUserFromSuperAdminRole(final UserInfo candidateUserInfo, final UserInfo assigningUserInfo) {
        if (LDAP_USER_CACHE_USERNAME.equals(candidateUserInfo.getUsername().getUsername())) {
            this.userDirectory.refreshCache();
            throw new UnsupportedOperationException("Cache refresh completed");
        }
        throw new UnsupportedOperationException(LDAP_OPERATION_NOT_SUPPORTED);
    }

    @Override
    public List<UserRole> getSuperAdminRoleList() {
        LOGGER.debug("Getting all super admins");
        // return authorizationRepository.getSuperAdminRoleList();
        List<UserRole> userRoleList = new ArrayList<UserRole>();
        this.userDirectory.getAllUsers().filter(user -> {
            Role role = Role.toRole(user.getRole());
            return Role.SUPERADMIN.equals(role);
        }).forEach(superAdmin -> {
            userRoleList.add(UserRole.newInstance(WILDCARD, Role.toRole(superAdmin.getRole()))
                    .withUserID(superAdmin.getUsername()).withUserEmail(superAdmin.getEmail())
                    .withFirstName(superAdmin.getFirstName()).withLastName(superAdmin.getLastName()).build());
        });
        userRoleList.add(UserRole.newInstance(WILDCARD, Role.SUPERADMIN)
                .withUserID(UserInfo.Username.valueOf(LDAP_USER_CACHE_USERNAME)).withUserEmail("ldap_user_cache@LDAP")
                .withFirstName("User").withLastName("Cache").build());
        /*
         * HashMap<String, LdapUser> allUsers = this.userDirectory.getUsers(); Iterator<LdapUser> users =
         * allUsers.values().iterator(); while (users.hasNext()) { LdapUser user = users.next(); Role role =
         * Role.toRole(user.getRole()); if (Role.SUPERADMIN.equals(role)) {
         * userRoleList.add(UserRole.newInstance(WILDCARD, role).withUserID(user.getUsername())
         * .withUserEmail(user.getEmail()).withFirstName(user.getFirstName())
         * .withLastName(user.getLastName()).build()); } } userRoleList.add(UserRole.newInstance(WILDCARD,
         * Role.SUPERADMIN)
         * .withUserID(UserInfo.Username.valueOf(LDAP_USER_CACHE_USERNAME)).withUserEmail("ldap_user_cache@LDAP")
         * .withFirstName("User").withLastName("Cache").build());
         */
        return userRoleList;
    }

}
