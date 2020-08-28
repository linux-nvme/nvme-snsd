#! /bin/sh
#
# nvme-snsd distribute build script
# 1、编译所有模块，生成结果到output [TODO]
# 2、在output下建立nvme-snsd-${version} 目录
# 3、拷贝生成结果到 nvme-snsd-${version} [TODO]
# 4、压缩nvme-snsd-${version}为zip，删除nvme-snsd-${version}目录
# 5、建立rpm目录，拷贝nvme-snsd-${version}.zip， *spec
# 6、执行rpm出包
#
cd $(dirname $0)/../
export VERSION_SNSD=$(sh SNSD-VERSION-GEN)
echo VERSION_SNSD:$VERSION_SNSD
cd -

source $(dirname $0)/../script/snsd_conf.sh

echo TOP_DIR:$TOP_DIR

## make output dir
echo OUTPUTDIR:$OUTPUT_DIR
if [ ! -d $OUTPUT_DIR ]; then
	mkdir $OUTPUT_DIR
fi

rm -rf $TARGET_DIR
mkdir $TARGET_DIR

## cp install file and systemd service
mkdir -p $TARGET_DIR/usr/bin
mkdir -p $TARGET_DIR/usr/share/doc
mkdir -p $TARGET_DIR/usr/lib/systemd/system
cp -af $SCRIPT_DIR/nvme-snsd.service $TARGET_DIR/usr/lib/systemd/system

## make
cd ${TOP_DIR}
make clean
make $1

cp -af ${TOP_DIR}/nvme-snsd $TARGET_DIR/usr/bin
cp -af ${TOP_DIR}/test/config/snsd.conf $TARGET_DIR/usr/share/doc/
make clean
 
## zip nvme-snsd-${version}
cd ${OUTPUT_DIR}
zip -r ${TARGET_DIR}.zip ${TARGET_BASE_DIR}
cd -

## rm nvme-snsd-${version} dir
rm -rf $TARGET_DIR

## build rpm
sh $SCRIPT_DIR/rpm_build.sh $2

## tar rpm
cd ${OUTPUT_DIR}
mkdir $2
ls ${TARGET_BASE_DIR}*.rpm || exit 1
mv ${TARGET_BASE_DIR}*.rpm ${OUTPUT_DIR}/$2
cd -

cd ${OUTPUT_DIR}/$2
md5sum ${TARGET_BASE_DIR}*.rpm > md5.txt
cd -

## clean 
cd ${OUTPUT_DIR}
rm -f ${TARGET_BASE_DIR}.zip
cd -

exit 0