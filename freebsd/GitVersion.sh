#!/bin/sh

GITVER=`git describe --dirty`
if [ $? -eq 0 ]; then
	echo "#define GIT_VERSION " \"$GITVER\"
	exit 0
fi

p4 cstat ... > /dev/null 2>&1
if [ $? -eq 0 ]; then
	P4VER=`p4 cstat ... |grep change |awk '{print $NF}'`
	echo "#define GIT_VERSION " \"$P4VER\"
else
	echo "#define GIT_VERSION " \"Unknown\"
fi
