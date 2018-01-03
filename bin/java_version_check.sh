#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'

# First find the installed version of java

if type -p java &> /dev/null; then
    _java=java
elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
    _java="$JAVA_HOME/bin/java"
else
    echo -e "${RED}WARNING:${NC} no Java version was found! Unable to verify java version dependancies"
fi

# Now compare the found version to the expected version

if [[ "$_java" ]]; then
    version=$("$_java" -version 2>&1 | awk -F '"' '/version/ {print $2}')
    #echo version "$version"
    if [[ "$version" != 1.8.* ]]; then
        echo -e "${RED}ERROR:${NC} Unexpected version of Java is installed ($version). Wasabi/maven plugin dependancies will cause build to fail. Use Java version 1.8.0_144"; 
	exit 1; 
    fi
fi
