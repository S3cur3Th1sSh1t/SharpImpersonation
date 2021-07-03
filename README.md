# SharpImpersonation

===========================    List user processes    ===========================

`SharpImpersonation.exe list`

===========================    List only elevated processes    ===========================

`SharpImpersonation.exe list elevated`

===========================    Impersonate the first process of <user> to start a new <binary>    ===========================

`SharpImpersonation.exe user:<user> binary:<binary-Path>`

======================  Inject shellcode into the first process of <user>  ======================

`SharpImpersonation.exe user:<user> shellcode:<base64shellcode>`

======================  Impersonate user <user> via ImpersonateLoggedOnuser for the current session  ======================

`SharpImpersonation.exe user:<user> technique:ImpersonateLoggedOnuser`