# Wasabi LDAP
**License:** [![Apache 2](http://img.shields.io/badge/license-Apache%202-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0) <br/>

## Project
This project is an extension to the [Wasabi](https://github.com/intuit/wasabi/) platform for A/B testing. Currently, Wasabi only supports authentication via a flat file with hardcoded username/passwords. Obviously this is not ideal even in a mid-size environment with changing resource and collaborating team members.

To support new authentication mechanisms, this project adds support for a cached directory service and provides a default implementation for connecting and using an LDAP server as the sole source of both authentication and authorization details.

### Features
* **Customizable** - Wasabi LDAP takes all parameters via configuration parameters. This allows you to customize to your specific LDAP configuration.
* **Extendible** - Though the design of this project is highly configurable, all of our classes are both extendable and OOP swappable. Configure where possible, extend where necessary!
* **Simplified security with increased performance** - All security is managed via LDAP--simplifying your user management. Furthermore, using encrypted passwords/cookies and a cached user directory, this project builds and extends existing Wasabi classes and functionality.

## Installation



## Extending Wasabi LDAP
Wasabi LDAP builds on the base interfaces of Wasabi. Below is an overview of key classes:
 ```java 
 package com.nhds.wasabi.ldap;
 
 public interface CachedUserDirectory extends UserDirectory {};
 
 public interface DirectoryDelegate {};
 
 package com.nhds.wasabi.ldap.impl;
 
 public class DirectoryAuthentication implements Authentication {};
 
 public class DirectoryAuthorization implements Authorization {};
 
 public class LdapDelegate implements DirectoryDelegate {};
 
 public class LdapUserDirectory implements CachedUserDirectory {};

```


