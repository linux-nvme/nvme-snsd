#! /bin/sh

source $(dirname $0)/snsd_conf.sh

## Get OS info
#KERNEL=`uname -r`
#KER_VER=${KERNEL%%-*}
#OS="euler-${KER_VER}"
#ARCH=${KERNEL##*.}
ARCH=$1

## Write conf info in .rpmmacros
rm ~/.rpmmacros -f
echo "%_topdir $RPM_BUILD_DIR" > ~/.rpmmacros
echo "%_SUBDIR target" >> ~/.rpmmacros
echo "%_VERSION $VERSION" >> ~/.rpmmacros
echo "%_RELEASE $ARCH" >> ~/.rpmmacros
echo "%_SOURCE ${TARGET_FILE_NAME}" >> ~/.rpmmacros

## mk rpm dir
rm -rf $RPM_BUILD_DIR
mkdir -p $RPM_BUILD_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

## copy snsd.spec
SRC_SPEC_FILE=$SCRIPT_DIR/snsd.spec
DEST_SPEC_FILE=$RPM_BUILD_DIR/SPECS/snsd.spec
cp $SRC_SPEC_FILE $DEST_SPEC_FILE -rf
dos2unix $DEST_SPEC_FILE 2> /dev/null
chmod +x $DEST_SPEC_FILE

## copy src file
cp $TARGET_FILE $RPM_BUILD_DIR/SOURCES/ -rf

## build rpm
rpmbuild -bb $DEST_SPEC_FILE --target $ARCH

cp -rf $RPM_BUILD_DIR/RPMS/$ARCH/*.rpm $OUTPUT_DIR
rm -rf $RPM_BUILD_DIR
