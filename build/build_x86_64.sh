BUILD_DIR=$(dirname $(readlink -f "$0"))

sh ${BUILD_DIR}/build.sh CC=gcc x86_64