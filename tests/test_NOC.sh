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

set -xeu
OUTDIR=`mktemp -d`

# getAuditView Test 10 - Provide a working period that has a few audit records
python src/porridge.py -P -S --cert-file=secret/test-fac_sign.p12 -o "$OUTDIR/good.csv" --date-from 2016-5-1 --date-to 2020-5-1 < secret/test-password.txt
grep -F --quiet 'getAuditView,2018-09-20 19:54:22.732000+10:00,,,,8003624900029833,Test Health Service 473,8003624900029833,Test Health Service 473,,Medicare,Self,8003608000179507,,IHI,8003608000179507,Create,Register for a Record,,,,,,,,,,'  "$OUTDIR/good.csv"

# getAuditView Test 11 - no dates
# Not done via the UI, which will pick default values
python tests/noc_test_11.py 2>&1 | grep -F --quiet "Request failed: PCEHR_ERROR_0003 - SOAP body fault"

# getAuditView Test 12 - provide a working period that has more than 500 audit records
# This period needs to be set up with the tests/send_requests.py tool for the right period
python src/porridge.py -P -S --cert-file=secret/test-fac_sign.p12 -o "$OUTDIR/fail.csv" --date-from 2020-5-20 --date-to 2020-5-23 < secret/test-password.txt
test ! -f "$OUTDIR/fail.csv"

# getAuditView Test 13 - Invalid HPIO and Time period
# Not done via the UI, which will always use the right HPIO from the certificate
python tests/noc_test_13.py 2>&1 | grep -F --quiet "Request failed: PCEHR_ERROR_0505 - Invalid HPI-O"

# Clean up
rm -r "$OUTDIR"
