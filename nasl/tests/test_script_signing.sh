#! /bin/sh

# Run the signature verification tests and print a summary of the tests.

export OPENVAS_GPGHOME=gnupg
NASL=../nasl/openvas-nasl

signed_file=signed.nasl
signed_file_sig=signed.nasl.asc

numok=0
numfailed=0

# USAGE: check_script SCRIPTNAME EXPECTED-RESULT
#
# Runs SCRIPTNAME and compares its stdout with EXPECTED-RESULT.  If
# they're equal, the test has passed. otherwise the test failed.
check_script() {
    echo -n "$1 "
    result=$($NASL $1 2> $1.err.log)
    if [ "x$result" == "x$2" ]; then
	numok=$((numok + 1))
	echo OK
    else
	numfailed=$((numfailed + 1))
	echo FAILED
    fi
}

# a signed script
check_script $signed_file YES

# an unsigned script.  No output is generated because the nasl
# interpreter will not even attempt to execute the file
unsigned=temp-unsigned.nasl
cp $signed_file $unsigned
check_script $unsigned ""

# an invalid signature. No output is generated because the nasl
# interpreter will not even attempt to execute the file
badsig=temp-badsig.nasl
cp $signed_file $badsig
cp $signed_file_sig $badsig.asc
echo "# modified" >> temp-badsig.nasl
check_script $badsig ""


# print summary
echo "-------------------------------"
echo "$((numok + numfailed)) tests, $numok ok, $numfailed failed"

# exit with non-zero status if any test has failed
if [ $numfailed -gt 0 ]; then
    exit 1
fi
