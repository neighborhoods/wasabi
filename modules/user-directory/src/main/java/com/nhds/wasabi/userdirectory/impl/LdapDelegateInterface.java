package com.nhds.wasabi.userdirectory.impl;

import com.intuit.wasabi.exceptions.AuthenticationException;

public interface LdapDelegateInterface {
    public void getUserCache(LdapUserDirectory userDirectory) throws AuthenticationException;
    public LdapUser getUserInfoByEmail(String email) throws AuthenticationException;
    public LdapUser getUserInfoByUsername(String username) throws AuthenticationException;
    public LdapUser authenticate(LdapUserDirectory ldapUserDirectory, String username, String password) throws AuthenticationException;
    public boolean isLdapTokenValid(LdapUserDirectory ldapUserDirectory, String username, String encryptedPassword);
}
