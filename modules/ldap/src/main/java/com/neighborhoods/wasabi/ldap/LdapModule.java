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
package com.neighborhoods.wasabi.ldap;

import static com.google.inject.Scopes.SINGLETON;
import static com.intuit.autumn.utils.PropertyFactory.create;
import static com.intuit.autumn.utils.PropertyFactory.getProperty;
import static java.lang.Class.forName;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.Properties;

import org.slf4j.Logger;

import com.google.inject.AbstractModule;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectoryModule;

/**
 * The Class LdapModule.
 * 
 * This method will dynamically bind impelementors of related interfaces at run time. Installation is not required to
 * use Wasabi-LDAP.
 */
public class LdapModule extends AbstractModule {

    /** The Constant PROPERTY_NAME. Where to retrieve the ldap properties. */
    public static final String PROPERTY_NAME = "/ldap.properties";

    /** The Constant LOGGER. */
    private static final Logger LOGGER = getLogger(LdapModule.class);

    @Override
    protected void configure() {
        LOGGER.debug("installing module: {}", LdapModule.class.getSimpleName());
        Properties properties = create(PROPERTY_NAME, LdapModule.class);
        String ldapClassName = getProperty("ldap.delegate.class", properties,
                "com.neighborhoods.wasabi.ldap.impl.LdapDelegate");

        Properties userDirectoryProperties = create(UserDirectoryModule.PROPERTY_NAME, UserDirectoryModule.class);
        String directoryClassName = getProperty("user.lookup.class.name", userDirectoryProperties,
                "com.neighborhoods.wasabi.ldap.impl.LdapUserDirectory");
        try {
            @SuppressWarnings("unchecked")
            Class<DirectoryDelegate> ldapImplClass = (Class<DirectoryDelegate>) forName(ldapClassName);

            bind(DirectoryDelegate.class).to(ldapImplClass).in(SINGLETON);

            @SuppressWarnings("unchecked")
            Class<CachedUserDirectory> directoryImplClass = (Class<CachedUserDirectory>) forName(directoryClassName);

            bind(CachedUserDirectory.class).to(directoryImplClass).in(SINGLETON);
        } catch (ClassNotFoundException e) {
            LOGGER.error("unable to find class: {}", e.getClass().toString(), e);

            throw new AuthenticationException("unable to find class: " + ldapClassName, e);
        }

        LOGGER.debug("installed module: {}", LdapModule.class.getSimpleName());
    }
}
