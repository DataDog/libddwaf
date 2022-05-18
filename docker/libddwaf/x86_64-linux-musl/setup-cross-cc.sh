#!/bin/sh

CTARGET="$1"
if [ -z "$CTARGET" ]; then
    program="$(basename "$0")"
    echo "usage: $program TARGET_ARCH"
    return 1
else
    echo "CTARGET=$CTARGET"
fi

# get abuild configurables
if [ ! -e /usr/share/abuild/functions.sh ]; then
    echo "abuild not found"
    exit 1
fi

. /usr/share/abuild/functions.sh

msg() {
    printf "$GREEN>>>${NORMAL} ${BLUE}bootstrap-${CTARGET_ARCH}${NORMAL}: %s\n" "$1" >&2
}

err() {
    printf "$RED>>> ERROR${NORMAL}: %s\n" "$*" >&2
}

die() {
    err "$*"
    exit 2
}

if [ -z "$CBUILD_ARCH" ]; then
    die "abuild is too old"
fi

# deduce aports directory
if [ -z "$APORTSDIR" ]; then
    APORTSDIR="$(realpath "$(dirname "$0")/../aports")"

    if [ ! -e "$APORTSDIR/main/build-base" ]; then
        die "Unable to deduce aports base checkout"
    fi
fi

echo "CBUILD=$CBUILD"
echo "CHOST=$CHOST"
echo "CBUILDROOT=$CBUILDROOT"
echo "APORTSDIR=$APORTSDIR"

APK="apk --root $CBUILDROOT"

if [ ! -d "$CBUILDROOT" ]; then
    msg "Creating sysroot in $CBUILDROOT"
    if [ -z "$PACKAGER_PRIVKEY" ] || [ ! -f "$PACKAGER_PRIVKEY" ]; then
        abuild-keygen -i -a || exit 2
        . ~/.abuild/abuild.conf
    fi

    APK_ROOT_CONF="$CBUILDROOT/etc/apk"
    mkdir -p "$APK_ROOT_CONF/keys"
    cp /etc/apk/repositories "$APK_ROOT_CONF/"
    case $CTARGET_ARCH in # HACK
        armv7)
            keypath=/usr/share/apk/keys/armhf
            ;;
        *)
            keypath=/usr/share/apk/keys/$CTARGET_ARCH
            ;;
    esac
    cp "$keypath"/* "$APK_ROOT_CONF/keys/"
    cp "$PACKAGER_PRIVKEY.pub" "$APK_ROOT_CONF/keys/"
    $APK add --update --initdb --arch "$CTARGET_ARCH" libc-dev libgcc ||
        die "failed to initialize target APK repository"
fi

export REPODEST="/across/packages"
mkdir -p "$REPODEST"

msg "Building cross-compiler"
export CBUILD CHOST CTARGET BOOTSTRAP=nobase

# Build and install cross binutils (--with-sysroot)
APKBUILD=$(aports_buildscript binutils) abuild -F -r ||
    die "failed to build binutils-$CTARGET_ARCH"

# Full cross GCC
EXTRADEPENDS_TARGET="musl musl-dev" \
    LANG_ADA=false LANG_D=false LANG_OBJC=false LANG_GO=false LANG_FORTRAN=false \
    APKBUILD=$(any_buildscript gcc) abuild -F -r ||
       die "failed to build gcc-$CTARGET_ARCH"

# Cross build-base
APKBUILD=$(aports_buildscript build-base) abuild -F -r ||
    die "failed to build build-base"

msg "Done"
echo "To install the cross-compiler use 'apk --repository $REPODEST/main --keys-dir ~/.abuild add build-base-$CTARGET_ARCH'"
echo "To build Alpine packages for '$CTARGET_ARCH' use 'CHOST=$CTARGET_ARCH abuild -r'"
echo "To explicitly install cross-build libraries use '$APK add --no-scripts <pkg>'"
