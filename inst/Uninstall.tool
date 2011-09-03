#!/bin/sh

export PATH="/bin:/usr/bin:/sbin:/usr/sbin:$PATH"

PKG=com.lab-fgb.9p
KEXT=com.lab-fgb.kext.9p
KEDIR=/System/Library/Extensions/9p.kext
FSDIR=/System/Library/FileSystems/9p.fs
NPDIR=/System/Library/FileSystems/NetFSPlugins/9p.bundle

DIRS=""
test -d $KEDIR && DIRS="$DIRS $KEDIR"
test -d $FSDIR && DIRS="$DIRS $FSDIR"
test -d $NPDIR && DIRS="$DIRS $NPDIR"

DBDIR=/var/db/receipts
FILES=""
test -f $DBDIR/$PKG.bom && FILES="$FILES $DBDIR/$PKG.bom"
test -f $DBDIR/$PKG.plist && FILES="$FILES $DBDIR/$PKG.plist"

if test -n "$FILES" -o -n "$DIRS"; then
    echo "The following files and directories will be removed:"
    for i in $FILES $DIRS; do
        echo "    $i"
    done
    sudo -p "Enter %u's password:" /bin/rm -fr $FILES $DIRS
fi

if /usr/sbin/kextstat -b $KEXT -l | grep -q $KEXT; then
	echo "The Kernel Extension $KEXT will be unloaded."
    sudo -p "Enter %u's password:" /sbin/kextunload -b $KEXT > /dev/null 2>&1
fi
exit 0
