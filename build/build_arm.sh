BUILD_DIR=$(dirname $(readlink -f "$0"))

sh ${BUILD_DIR}/build.sh CC=aarch64-linux-gnu-gcc aarch64
