#! /bin/sh

# My Health Record NOC testing for GetAuditView
#
# Copyright © 2020 David Adam <mail@davidadam.com.au>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

if [ -z ${NOC_TEST_DIR+x} ]; then
    echo "Run with a fully-qualified path in the NOC_TEST_DIR environment variable to log all requests & responses."
fi

set -xeu
OUTDIR=`mktemp -d`

export PYTHONPATH=src:${PYTHONPATH:-}

# getAuditView Test 10 - Provide a working period that has a few audit records
${NOC_TEST_DIR+env MHR_LOG=${NOC_TEST_DIR}/noc_test_10} python src/porridge.py -P -S --cert-file=secret/test-fac_sign.p12 -o "$OUTDIR/good.csv" --date-from 2021-08-01 --date-to 2021-08-16 --time-to 23:40 < secret/test-password.txt
grep -E --quiet 'getAuditView,2021-08-16 23:38:26\.327000\+10:00,,,,8003628233368719,Test Health Service 1045,8003628233368719,Test Health Service 1045,,david,External Provider,\d+,\w+,IHI,\d+,Update,Access Record,,,,,,,,,EmergencyAccess,'  "$OUTDIR/good.csv"

# getAuditView Test 11 - no dates
# Not done via the UI, which will pick default values
${NOC_TEST_DIR+env MHR_LOG=${NOC_TEST_DIR}/noc_test_11} python tests/noc_test_11.py 2>&1 | grep -F --quiet "Request failed: PCEHR_ERROR_0003 - SOAP body fault"

# getAuditView Test 12 - provide a working period that has more than 500 audit records
# This period needs to be set up with the tests/send_requests.py tool for the right period
${NOC_TEST_DIR+env MHR_LOG=${NOC_TEST_DIR}/noc_test_12} python src/porridge.py -P -S --cert-file=secret/test-fac_sign.p12 -o "$OUTDIR/fail.csv" --date-from 2021-08-01 --date-to 2021-08-16 --time-to 23:43 < secret/test-password.txt
test ! -f "$OUTDIR/fail.csv"

# getAuditView Test 13 - Invalid HPIO and Time period
# Not done via the UI, which will always use the right HPIO from the certificate
${NOC_TEST_DIR+env MHR_LOG=${NOC_TEST_DIR}/noc_test_13} python tests/noc_test_13.py 2>&1 | grep -F --quiet "Request failed: PCEHR_ERROR_0505 - Invalid HPI-O"

# Clean up
rm -r "$OUTDIR"
