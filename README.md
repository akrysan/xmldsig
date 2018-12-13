# xmldsig

Sign/verify XML by xmldsig specification. Developed for signing SAML2 metadata.

Usage:

1. sign XML

**xmldsig -sign -xmlpath=[XMLPATH] -certpath=[CERTPATH] -password=[PASS]**

2. verify XML signature

**xmldsig -verify -xmlpath=[XMLPATH]**
