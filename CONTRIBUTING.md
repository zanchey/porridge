# Contributing to MHROAT

Thanks for your interest in MHROAT. As free, open-source software, you are able to modify and redistribute the program (with certain caveats) as described in the [GNU General Public License ](LICENSE.txt). However, you may wish to contribute your changes back to this original repository so that they can be included for everyone's use:

This document outlines:

* Overall technical approach
* Submitting fixes and changes
* Forking and getting started with My Health Record Development

MHROAT is sometimes internally referred to as "porridge" (MHR oats), in the tradition of weak puns for programming projects.

## Implementation

The Australian My Health Record system exposes a number of interfaces which are available for clinical information systems to connect to. They are documented in the PCEHR Implementation Guide. The only interface used by MHROAT is the `getAuditView` interface:

> The getAudit operation is responsible for returning an audit trail from the audit logs of either a healthcare provider organisation (HPI-O) or an individual (IHI). If the request is from a healthcare provider organisation, the PCEHR System provides all audit events for the provider across multiple PCEHRs...
>
> The information provided is constrained by the requestor’s access rights and role in the PCEHR System. The healthcare provider organisation is able to access only a subset of the audit events.

`getAuditView` therefore allows a healthcare organisation to download a list of all interactions made on behalf of that organisation for a given time range.

MHROAT works by:
* Loading a certificate and extracting the target HPI-O
* Connecting to the My Health Record system
* Downloading all audit events for the HPI-O in the given date range
* Flattening the returned XML audit trail into an array
* Writing this to disk as a CSV

Notably, because MHROAT does not download or upload individual patient documents, no connection to the Australian Healthcare Identifiers service is required.

## Submitting fixes and changes

If you identify a problem with the program, you can report an issue in the [GitHub public issue tracker](https://github.com/zanchey/porridge/issues).

Pull requests are accepted through [GitHub](https://github.com/zanchey/porridge/pulls).

## Forking and getting started with My Health Record development

Although the source code will build and run as distributed, it is not able to connect either to the development or production My Health Record systems. This is because of legal restrictions on making these connections and sharing the technical artifacts that are required to make the connections. This is not particularly compatible to open source/Free Software models of collaborative development, but if you become a registered developer then you can take this source code, modify it, then have it certified and tested and then distribute it yourself.

To connect to the development system, you must:

* [Register as a My Health Record developer](https://developer.digitalhealth.gov.au/resources/faqs/my-health-record-initial-registration) 
* Submit a software vendor details form which includes the appropriate 
* Acquire appropriate National Authentication Standards for Health test certificates
* Recieve a test plan which includes appropriate endpoints

Once you have completed these steps, you should be able to create a `src/config.py` file from the `src/config-example.py` which contains your identifiers and endpoints.

You can then complete NOC testing and have your software certified for connection.

Please remove or modify the logo if you decide to distribute your own version.