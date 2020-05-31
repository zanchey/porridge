# Script to run a NOC test for the MHR
# For testing use
# Copyright © 2020 David Adam <mail@davidadam.com.au>

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


import sys

sys.path.insert(0, "src")

import mhr
import datetime
from config import mhr_config

mhr_config["schema_path"] = "resources/pcehr_schema"

cert_file = "secret/test-fac_sign.p12"
cert_pass = open("secret/test-password.txt", "r").read().strip()

interface = mhr.MyHealthRecordInterface(cert_file, cert_pass, mhr_config)
# Lucky Python doesn't have protected properties!
interface.hpio = "8003628233364924"
now = datetime.datetime.now()
audit_records = interface.getAuditView(
    now + datetime.timedelta(days=2), now + datetime.timedelta(days=5)
)
