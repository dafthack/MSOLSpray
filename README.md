# MSOLSpray
A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled. 

BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

## Why another spraying tool?
Yes, I realize there are other password spraying tools for O365/Azure. The main difference with this one is that this tool not only is looking for valid passwords, but also the extremely verbose information Azure AD error codes give you. These error codes provide information relating to if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, if the account is disabled, if the password is expired and much more.

So this doubles, as not only a password spraying tool but also a Microsoft Online recon tool that will provide account/domain enumeration. In limited testing it appears that on valid login to the Microsoft Online OAuth2 endpoint it isn't auto-triggering MFA texts/push notifications making this really useful for finding valid creds without alerting the target.

Lastly, this tool works well with [FireProx](https://github.com/ustayready/fireprox) to rotate source IP addresses on authentication requests. In testing this appeared to avoid getting blocked by Azure Smart Lockout.

**Brought to you by:**

[<img src="https://www.blackhillsinfosec.com/wp-content/uploads/2016/03/BHIS-logo-L-300x300.png">](https://www.blackhillsinfosec.com)

## Quick Start
You will need a userlist file with target email addresses one per line. Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass'.

```PowerShell
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
```

### Invoke-MSOLSpray Options
```
UserList  - UserList file filled with usernames one-per-line in the format "user@domain.com"
Password  - A single password that will be used to perform the password spray.
OutFile   - A file to output valid results to.
Force     - Forces the spray to continue and not stop when multiple account lockouts are detected.
URL       - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
```
