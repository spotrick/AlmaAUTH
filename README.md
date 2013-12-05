Authentication with Alma/LDAP
=============================

Perl modules for authenticating web services using Alma and LDAP.

The package also includes a "CGI hook" perl script for use with 
Primo user login.

Login would normally be done with an institutional LDAP username
and password. After successful authentication with LDAP, the Alma
user record must be found to provide the Alma primary identifier.

The modules also allow for an alternative login using barcode and
last name (the "traditional" Voyager method).

To use, you will also need the AlmaWS package, available separately
from github.

