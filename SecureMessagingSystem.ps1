function SecureMessagingSystem {
    
    [Alias('SMS')]

    Param (
        [switch] $Send,         # Main
        [string] $Message,
        [int]    $Key,
        [string] $TargetUser,

        [switch] $Retrieve,     # Main

        [switch] $Credentials,  # Main

        [switch] $Check,        # Main
        [switch] $Raw
        
    )

    # Main Functions
    function Send-SMS {

        # Establish JSON Fields
        if ($Key) { $Encrypted = $TRUE }
        else { $Encrypted = $FALSE }

        $EncMessage = Fucky64-Encrypt
        $Timestamp = Get-Date -Format "dddd MM/dd/yyyy HH:mm"


        # Send Encoded / Encrypted Message

        [pscustomobject]$Body = @{
            'message'       = $EncMessage
            'encrypted'     = $Encrypted
            'timestamp'     = $Timestamp
            'targetUser'    = $TargetUser
            'sender'        = $Username
            'password'      = $Password
        }

        (Invoke-WebRequest -Uri "$RootURL/send" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body ($Body | ConvertTo-Json) -Method POST).content
    }
    function Retrieve-SMS {

        # Retrieve Encoded / Encrypted Message

        [pscustomobject]$Body = @{
            'targetUser'    = $Username
            'password'      = $Password
        }

        $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body ($Body | ConvertTo-Json) -Method GET).content

        try {

            # Parse JSON Fields
            $Encrypted = ($Response | ConvertFrom-Json).encrypted
            $Timestamp = ($Response | ConvertFrom-Json).timestamp
            $Sender = ($Response | ConvertFrom-Json).sender
            $EncMessage = ($Response | ConvertFrom-Json).message
        

            # Encrypted Message
            if ($Encrypted -eq $TRUE) {

                $Increment = 1
                while ($TRUE) {
                    
                    # Exit ; Exceeded Three Attempts
                    if ($Increment -gt 3) { return (Write-Host 'MESSAGE DELETED' -ForegroundColor Red) }

                    if (!$Key) {   
                                     
                        Write-Host "[$Increment/3] " -ForegroundColor Red -NoNewline
                        Write-Host "Enter decryption key: " -ForegroundColor Yellow -NoNewline
                        $Key = Read-Host
                    }

                    try { $Message = Fucky64-Decrypt }
                    catch { if ($Increment -ne 3) { Write-Host "Invalid key. " -ForegroundColor Red } }
                    
                    # Reset if Decryption Failed
                    if (!$Message) { $Key = $NULL ; $Increment++ }
                    else { break }
                }
            }
            
            # Encoded Message
            else { $Message = Fucky64-Decrypt }


            # Final Output
            Write-Host "Message     | " -ForegroundColor Yellow -NoNewline ; $Message
            Write-Host "Timestamp   | " -ForegroundColor Yellow -NoNewline ; $TimeStamp
            Write-Host "Sender      | " -ForegroundColor Yellow -NoNewline ; $Sender
        }

        catch { $Response }
    }
    function Check-Messages {

        $Response = (Invoke-WebRequest "$RootURL/master" -SkipCertificateCheck -Method GET).content

        try { $Output = $Response | ConvertFrom-Json }
        catch { return $Response }


        if ($TargetUser) {
            $TargetUser = $TargetUser.ToUpper()
            $Output = $Output | ? {$_.TargetUser -eq $TargetUser }

            $MsgTotal = $Output.count
            $Message = "User '$TargetUser' has '$MsgTotal' pending message(s)."
        }
        else {
            $MsgTotal = $Output.count
            $Message = "Total of '$MsgTotal' pending message(s)."
        }

        if ($Raw) { $Output }
        Write-Host $Message
    }
    function User-Creds {

        $CredPath = "$PSScriptRoot/var/creds.ini"
        
        if ((Test-Path $CredPath) -and !($Credentials)) {
            return (Get-Content $CredPath)
        }

        Write-Host 'CREDENTIAL CREATION' -ForegroundColor Red

        # Username Input
        while ($TRUE) {
            Write-Host 'Enter Username: ' -ForegroundColor Yellow -NoNewline ; $CredUser = Read-Host
            if (($CredUser -like "*'*") -or ($CredUser -like "*`"*")) { Write-Host 'Invalid user input.' -ForegroundColor Red }
            else { break }
        }
        # Password Input
        while ($TRUE) {
            Write-Host 'Enter Password: ' -ForegroundColor Yellow -NoNewLine ; $CredPass = Read-Host
            if ($CredPass -like "* *") { Write-Host 'Invalid user input.' -ForegroundColor Red }
            else { break }
        }
        # Server Input
        $IPRegex = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'
        while ($TRUE) {
            Write-Host 'Enter Server URL: ' -ForegroundColor Yellow -NoNewline ; $RootURL = Read-Host

            # Verify server is reachable
            if ((($RootURL -match 'http://') -or ($RootURL -match 'https://')) -and ($RootURL -match $IPRegex)) {
                $ServerIP = $Matches[0]
                $ServerPort = $RootURL.Split($ServerIP+":")[-1]

                # Added to fix Linux compatibility
                if ($isLinux) { $Results = $TRUE }
                
                else {
                    $Results = (Test-NetConnection -RemoteAddress $ServerIP -Port $ServerPort).TCPTestSucceeded
                }

                if ($Results) { break }
            }
            else { Write-Host 'Invalid user input.' -ForegroundColor Red }
        }

        # Send New Credentials to Server
        [pscustomobject]$CredObject = @{
            'username'  = $CredUser.ToUpper()
            'password'  = $CredPass
            'server'    = $RootURL
        }

        if (!(Test-Path "$PSScriptRoot/var")) { mkdir "$PSScriptRoot/var" | Out-Null }
        Set-Content $CredPath -Value ($CredObject | ConvertTo-Json)
        (Invoke-WebRequest -Uri "$RootURL/update" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body ($CredObject | ConvertTo-Json) -Method POST).content | Out-Null

        return ($CredObject | ConvertTo-Json)
    }

    # Import Fucky64
    . $PSScriptRoot/lib/Fucky64-Abridged.ps1

    # Acquire / Update User Credentials
    $CredObject = User-Creds

    # Exit
    if (($Send -eq $FALSE) -and ($Retrieve -eq $FALSE) -and ($Check -eq $FALSE) -and ($Credentials -eq $FALSE)) { 
        return (Write-Host 'No method selected.' -ForegroundColor Red)
    }

    $RootURL = ($CredObject | ConvertFrom-Json).server
    $Username = ($CredObject | ConvertFrom-Json).username
    $Password = ($CredObject | ConvertFrom-Json).password

    # Prompt for Mandatory Parameters
    if ($Send -eq $TRUE) {
        $ErrorActionPreference = 'SilentlyContinue'
        if (!$Message) { Write-Host 'Enter Message: ' -ForegroundColor Yellow -NoNewline ; $Message = Read-Host }
        if (!$Key) { Write-Host 'Enter Encryption Key: ' -ForegroundColor Yellow -NoNewline ; $Key = ($Key = Read-Host) -as [int] }
        if ((!$TargetUser) -and (!$Check)) { Write-Host 'Enter TargetUser: ' -ForegroundColor Yellow -NoNewline ; $TargetUser = Read-Host }
    }

    # Minor error catching
    if ((!$Message) -and ($Send -eq $TRUE)) { return (Write-Host 'Invalid message input.' -ForegroundColor Red) }
    if (($TargetUser -like "*'*") -or ($TargetUser -like "*`"*")) { return (Write-Host 'Invalid user input.' -ForegroundColor Red) }
    $TargetUser = $TargetUser.ToUpper()

    
    if ($Send) { Send-SMS }                 # Send Messages
    elseif ($Retrieve) { Retrieve-SMS }     # Retrieve Messages
    elseif ($Check) { Check-Messages }      # Check Pending Messages
}