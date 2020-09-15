#!/bin/bash

SNSD_UT=snsd_ut

LCOV_OPTS="
	--rc lcov_branch_coverage=1
	--rc lcov_function_coverage=1
	--rc genhtml_branch_coverage=1
	--rc genhtml_function_coverage=1
	--rc genhtml_legend=1
	"
LCOV="lcov $LCOV_OPTS"
GENHTML_OPTS="
	--function-coverage
	--branch-coverage
	"
GENHTML="genhtml $GENHTML_OPTS"

if hash lcov; then
	has_cov="yes"
else
	has_cov="no"
fi

make clean
make
if [ ! -f $SNSD_UT ]; then
	echo "ERROR: Failed to make $SNSD_UT!"
	exit 1
fi

chmod +x $SNSD_UT
./$SNSD_UT

echo "==========================================="
echo "NOTE: All unit tests completed!"
echo "==========================================="

if [ "$has_cov" = "yes" ]; then
	$LCOV -q -d ../../ -b . -c -o snsd_ut.cov.all
	$LCOV -q --remove snsd_ut.cov.all '*/usr/include/*' '*/mockcpp/*' -o snsd_ut.cov.info
	$GENHTML -q snsd_ut.cov.info -o snsd_ut_cov
	rm -f snsd_ut.cov.info snsd_ut.cov.all
	echo "NOTE: Coverage report is here: snsd_ut_cov/"
	echo "==========================================="
else
	echo "WARN: lcov is not installed!"
fi

make clean
exit 0
