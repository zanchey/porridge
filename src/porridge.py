#! /usr/bin/env python3

# My Health Record Organisational Audit Tool (Porridge) - user interface
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

import csv, multiprocessing, sys
from os import path
from multiprocessing import Process, Pipe
import wx, wx.adv, wx.xrc as xrc
import logging
import mhr
import zeep
import getpass
import keyring
from datetime import datetime, date, time
from config import mhr_config

ABOUT_TEXT = """My Health Record Organisational Audit Tool (Porridge)
Version 1.0
Copyright © 2020 David Adam <mail@davidadam.com.au>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

if hasattr(sys, "_MEIPASS"):
    res_path = path.join(sys._MEIPASS, "resources")
else:
    res_path = path.join(path.abspath(path.curdir), "resources")

mhr_config["schema_path"] = path.join(res_path, "pcehr_schema")

GETAUDITVIEW_HEADERS = (
    "businessEvent",
    "eventTimeStamp",
    "auditEvent.auditEventID",
    "auditEvent.participantDetails.providerID",
    "auditEvent.participantDetails.providerName",
    "auditEvent.participantDetails.accessingHPIO",
    "auditEvent.participantDetails.accessingHPIOName",
    "auditEvent.participantDetails.participatingHPIO",
    "auditEvent.participantDetails.participatingHPIOName",
    "auditEvent.participantDetails.userID",
    "auditEvent.participantDetails.userName",
    "auditEvent.participantDetails.displayRole",
    "auditEvent.accessedEntity.ihiNumber",
    "auditEvent.accessedEntity.ihiName",
    "auditEvent.accessedEntity.subjectType",
    "auditEvent.accessedEntity.subject",
    "auditEvent.participantAction.actionType",
    "auditEvent.participantAction.operationPerformed",
    "auditEvent.participantAction.reason",
    "auditEvent.participantAction.approvalDateTime",
    "auditEvent.participantAction.approvalRole",
    "auditEvent.participantAction.approvalName",
    "auditEvent.participantAction.statusPriorDeactivation",
    "auditEvent.accessConditions",
    "auditEvent.accessConditions.accessLevel",
    "auditEvent.accessConditions.accessPermission",
    "auditEvent.accessConditions.accessConditions",
    "logEvent",
)


def flatten_xsd(d, prefix=""):
    """Flattens a XSD tree into a sequence of key, value tuples.
    
    Works best when wrapped in dict()."""
    for k in d:
        if isinstance(d[k], zeep.xsd.valueobjects.CompoundValue):
            yield from flatten_xsd(d[k], prefix=prefix + k + ".")
        elif d[k]:
            yield (prefix + k, d[k])
        else:  # Handles None elements
            yield (prefix + k, "")


def wx_to_pydate(wxdate):
    # Adapted from https://www.blog.pythonlibrary.org/2014/08/27/wxpython-converting-wx-datetime-python-datetime/
    assert isinstance(wxdate, wx.DateTime)
    if wxdate.IsValid():
        ymd = map(int, wxdate.FormatISODate().split("-"))
        return date(*ymd)
    else:
        return None


# GUI
class PorridgeApp(wx.App):
    def OnInit(self):
        self.res = xrc.XmlResource(path.join(res_path, "mhroat.xrc"))

        self.args_window = self.res.LoadFrame(None, "winArgs")
        xrc.XRCCTRL(self.args_window, "m_startDate").SetValue(
            wx.DateTime.Now().SetDay(1)
        )
        xrc.XRCCTRL(self.args_window, "m_endDate").SetValue(
            wx.DateTime.Now().SetToLastMonthDay()
        )

        xrc.XRCCTRL(self.args_window, "m_startTime").SetTime(0, 0, 0)
        xrc.XRCCTRL(self.args_window, "m_endTime").SetTime(23, 59, 59)

        xrc.XRCCTRL(self.args_window, "wxID_HELP").Bind(wx.EVT_BUTTON, self.ShowAbout)
        xrc.XRCCTRL(self.args_window, "wxID_OK").Bind(wx.EVT_BUTTON, self.Start)

        xrc.XRCCTRL(self.args_window, "m_certPicker").Bind(
            wx.EVT_FILEPICKER_CHANGED, self.GetPass
        )

        # About
        self.about_dialog = self.res.LoadDialog(self.args_window, "winAbout")
        xrc.XRCCTRL(self.about_dialog, "m_abouttext").SetLabelText(ABOUT_TEXT)
        self.about_dialog.Fit()

        # Process window
        # Reconstructed each time
        self.progress_window = None

        self.args_window.Show()
        return True

    def GetPass(self, event):
        try:
            saved_pass = keyring.get_password(
                "MHROAT", xrc.XRCCTRL(self.args_window, "m_certPicker").Path
            )
        except keyring.errors.KeyringError:
            # There's really nothing that can be acted on here, so don't show any errors
            # If there are bug reports about saved passwords not loading, this might be a good place to start
            return True
        if saved_pass:
            xrc.XRCCTRL(self.args_window, "m_certPass").Value = saved_pass
        return True

    def ErrDialog(self, message):
        return wx.MessageDialog(
            self.args_window, message, caption="Error", style=wx.OK | wx.ICON_ERROR
        ).ShowModal()

    def Start(self, event):
        ## Check that the form is filled in
        if not xrc.XRCCTRL(self.args_window, "m_certPicker").Path:
            return self.ErrDialog("Please choose a HPI-O certificate.")
        if not xrc.XRCCTRL(self.args_window, "m_outputPicker").Path:
            return self.ErrDialog("Please provide an output filename.")
        # Check that the dates are valid
        if xrc.XRCCTRL(self.args_window, "m_startDate").Value.IsLaterThan(
            xrc.XRCCTRL(self.args_window, "m_endDate").Value
        ):
            return self.ErrDialog("Start date must be before end date.")

        cert_file = xrc.XRCCTRL(self.args_window, "m_certPicker").Path
        cert_pass = xrc.XRCCTRL(self.args_window, "m_certPass").Value
        startdate = wx_to_pydate(xrc.XRCCTRL(self.args_window, "m_startDate").Value)
        starttime = time(*xrc.XRCCTRL(self.args_window, "m_startTime").GetTime())
        enddate = wx_to_pydate(xrc.XRCCTRL(self.args_window, "m_endDate").Value)
        endtime = time(*xrc.XRCCTRL(self.args_window, "m_endTime").GetTime())

        datetime_from = datetime.combine(startdate, starttime)
        datetime_to = datetime.combine(enddate, endtime)

        # Save password if requested
        if xrc.XRCCTRL(self.args_window, "m_savePass").Value:
            try:
                keyring.set_password("MHROAT", cert_file, cert_pass)
            except keyring.errors.KeyringError:
                pass

        # Load the progress dialog
        self.progress_window = self.res.LoadDialog(self.args_window, "winProgress")
        self.progress_window.text_out = xrc.XRCCTRL(self.progress_window, "m_textOut")
        self.progress_window.b_cancel = xrc.XRCCTRL(self.progress_window, "wxID_CANCEL")
        self.progress_window.b_ok = xrc.XRCCTRL(self.progress_window, "wxID_OK")
        self.progress_window.b_ok.Hide()

        # Set up the subprocess
        # Single-duplex pipe
        recv, send = Pipe(duplex=False)
        self.progress_window.pipe = recv
        # Subprocess object
        self.progress_window.process = Process(
            target=run,
            args=(
                send,
                cert_file,
                cert_pass,
                datetime_from,
                datetime_to,
                xrc.XRCCTRL(self.args_window, "m_outputPicker").Path,
            ),
        )

        # Set up the event handlers
        self.progress_window.Bind(wx.EVT_IDLE, self.Update)
        self.progress_window.b_cancel.Bind(wx.EVT_BUTTON, self.Stop)

        # Off we go...
        self.progress_window.process.start()
        # Close our copy of the pipe https://stackoverflow.com/a/20630199/125549
        send.close()
        self.progress_window.ShowModal()
        return True

    def Update(self, event):
        if not self.progress_window.process._closed:
            try:
                if self.progress_window.pipe.poll():
                    mytext = self.progress_window.pipe.recv() + "\n"
                    self.progress_window.text_out.AppendText(mytext)
            # poll() can raise BrokenPipeError on Windows, see https://bugs.python.org/issue41008
            except (EOFError, BrokenPipeError):
                self.Done(None)
        return True

    def Stop(self, event):
        self.progress_window.process.terminate()
        return self.Done(None)

    def Done(self, event):
        if self.progress_window.process.is_alive():
            self.progress_window.process.join()
        self.progress_window.process.close()
        self.progress_window.b_cancel.Hide()
        self.progress_window.b_ok.Show()
        return True

    def ShowAbout(self, event):
        self.about_dialog.ShowModal()
        return True


# CLI
def cli_app():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cert-file", help="Certificate file", required=True)
    parser.add_argument(
        "-P",
        "--prompt-password",
        action="store_true",
        help="Always prompt for password",
    )
    parser.add_argument(
        "-S", "--no-store-password", action="store_true", help="Never store password"
    )
    parser.add_argument(
        "-f",
        "--date-from",
        type=date.fromisoformat,
        default=date.today().replace(day=1),
        help="Audit start date (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--time-from",
        type=lambda s: datetime.strptime(s, "%H:%M"),
        default=None,
        help="Audit start time (HH:MM, 24-hour format)",
    )
    parser.add_argument(
        "-t",
        "--date-to",
        type=date.fromisoformat,
        default=date.today(),
        help="Audit end date (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--time-to",
        type=lambda s: datetime.strptime(s, "%H:%M"),
        default=None,
        help="Audit end time (HH:MM, 24-hour format)",
    )
    parser.add_argument("-o", "--output-file", required=True)
    args = parser.parse_args()

    datetime_from = args.date_from
    if args.time_from:
        datetime_from = datetime.combine(args.date_from, args.time_from.time())

    datetime_to = args.date_to
    if args.time_to:
        datetime_to = datetime.combine(args.date_to, args.time_to.time())

    cert_pass = None
    try:
        cert_pass = keyring.get_password("MHROAT", args.cert_file)
    except keyring.errors.KeyringError:
        print("Warning: keyring could not be loaded; no saved passwords read.")
    if not cert_pass or args.prompt_password:
        if sys.stdin.isatty():
            cert_pass = getpass.getpass("Certificate file password: ")
        else:
            cert_pass = sys.stdin.readline().strip()
        if not args.no_store_password:
            try:
                keyring.set_password("MHROAT", args.cert_file, cert_pass)
            except keyring.errors.PasswordSetError:
                print("Warning: password not saved.")

    # Set up the subprocess
    # Single-duplex pipe
    recv, send = Pipe(duplex=False)

    # Subprocess object
    process = Process(
        target=run,
        args=(
            send,
            args.cert_file,
            cert_pass,
            datetime_from,
            datetime_to,
            args.output_file,
        ),
    )
    process.start()
    # Close our copy of the pipe https://stackoverflow.com/a/20630199/125549
    send.close()

    while True:
        try:
            print(recv.recv())
        except EOFError:
            process.join()
            break


class PipeHandler(logging.Handler):
    """This logging handler sends events as text over a pipe."""

    def __init__(self, pipe):
        logging.Handler.__init__(self)
        self.pipe = pipe

    def emit(self, record):
        try:
            self.pipe.send(self.format(record))
        except:
            self.handleError(record)


def run(output_socket, cert_file, cert_pass, date_from, date_to, output_file):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=(PipeHandler(output_socket),),
    )

    try:
        interface = mhr.MyHealthRecordInterface(cert_file, cert_pass, mhr_config)
        audit_records = interface.getAuditView(date_from, date_to)
        if not audit_records:
            # Success but no records; write an empty file
            audit_records = ()
        with open(output_file, "w") as out:
            writer = csv.DictWriter(
                out, fieldnames=GETAUDITVIEW_HEADERS, extrasaction="raise"
            )
            writer.writeheader()
            writer.writerows(
                dict(flatten_xsd(audit_record)) for audit_record in audit_records
            )

    except mhr.MyHealthRecordError as e:
        pass
    except Exception as e:
        logging.exception("Unhandled exception", exc_info=e)

    finally:
        output_socket.close()


def main():
    multiprocessing.freeze_support()
    multiprocessing.set_start_method(
        "spawn"
    )  # Per https://bugs.python.org/issue33725, fork isn't safe on macOS

    if len(sys.argv) > 1:
        # CLI mode
        cli_app()
    else:
        # GUI mode
        app = PorridgeApp()
        app.MainLoop()


if __name__ == "__main__":
    main()
