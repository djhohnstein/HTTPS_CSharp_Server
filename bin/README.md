Some Examples:

```
rundll32.exe C:\Users\Mobile\Downloads\HTTPProxy-src\bin\Release\HTTPProxyServer.dll,EntryPoint

Regsvr32.exe /s HTTPProxyServer.dll

odbcconf.exe /a {REGSVR HTTPProxyServer.dll}

 C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /u .\HTTPProxyServer.dll
 
```

You will need to run these hosts as admin.

Configure your browser manually to point to your listening port

You will need to create the seed , root CA see `Invoke-CreateCertificate`

TODO: Combine all this to make it complete.


Experimental, early prototype, use are your own risk lol.


