function SecureMessagingSystem {
#.SYNOPSIS
# Volatile dual encryption messaging system.
# ARBITRARY VERSION NUMBER:  0.6.9
# AUTHOR:  Tyler McCann (@tyler.rar)
#
#.DESCRIPTION
# Placeholder
#
# Recommendations:
# -- Placeholder
#
# Parameters:
#    -Send          -->   Send message
#    -Retrieve      -->   Retrieve message
#    -Credentials   -->   Input / Modify user credentials with server
#    -Check         -->   (Debug) Return quantity of pending messages
#    -Raw           -->   (Debug) Return pending message data fields
#    -Help          -->   Return Get-Help page
#    
# Example Usage:
#    []  PS C:\Users\Bobby> 
#
#.LINK
# https://github.com/tylerdotrar/SMS

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
        #$Timestamp = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
        
        $TZArray = ((Get-TimeZone).StandardName).split(' ')
        foreach ($Word in $TZArray) { $TimeZone += $Word[0] }

        $TimeStamp = Get-Date -Format "MM/dd/yyyy HH:mm $TimeZone"

        # Send Encoded / Encrypted Message

        [pscustomobject]$Body = @{
            'message'       = $EncMessage
            'encrypted'     = $Encrypted
            'timestamp'     = $Timestamp
            'targetUser'    = $TargetUser
            'sender'        = $Username
            'password'      = $Password
        } | ConvertTo-Json


        if ($PSEdition -eq 'Core') { 
            (Invoke-WebRequest -Uri "$RootURL/send" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $Body -Method POST).content
        }
        else {
            (Invoke-WebRequest -Uri "$RootURL/send" -ContentType "application/json; charset=utf-8" -Body $Body -Method POST).content
        }
    }
    function Retrieve-SMS {

        # Retrieve Encoded / Encrypted Message

        [pscustomobject]$Body = @{
            'targetUser'    = $Username
            'password'      = $Password
        } | ConvertTo-Json


        if ($PSEdition -eq 'Core') {
            $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $Body -Method GET).content
        }
        else {
            $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -ContentType "application/json; charset=utf-8" -Body $Body -Method GET).content
        }


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

        if ($PSEdition -eq 'Core') {
            $Response = (Invoke-WebRequest "$RootURL/master" -SkipCertificateCheck -Method GET).content
        }
        else { 
            $Response = (Invoke-WebRequest "$RootURL/master" -Method GET).content
        }


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
            return (Get-Content $CredPath | ConvertFrom-Json )
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
                $ServerPort = $RootURL.Split(':')[-1]

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
        } | ConvertTo-Json


        if (!(Test-Path "$PSScriptRoot/var")) { mkdir "$PSScriptRoot/var" | Out-Null }
        Set-Content $CredPath -Value $CredObject


        if ($PSEdition -eq 'Core') {
            Invoke-WebRequest -Uri "$RootURL/update" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $CredObject -Method POST | Out-Null
        }
        else {
            Invoke-WebRequest -Uri "$RootURL/update" -ContentType "application/json; charset=utf-8" -Body $CredObject -Method POST | Out-Null
        }
        

        return $CredObject
    }
    function HTTPS-Bypass ([switch]$Undo) {

        if ($Undo) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $NULL }

        else {

            # [!] Required by non-Core PowerShell for self-signed certificate bypass (HTTPS).
            $CertBypass = @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class SelfSignedCerts
{
    public static void Bypass()
    {
        ServicePointManager.ServerCertificateValidationCallback = 
            delegate
            (
                Object obj, 
                X509Certificate certificate, 
                X509Chain chain, 
                SslPolicyErrors errors
            )
            {
                return true;
            };
    }
        
}
'@
            Add-Type $CertBypass
            [SelfSignedCerts]::Bypass()
        }
    }


    # Return if No Parameter Selected
    if ((!$Send) -and (!$Retrieve) -and (!$Check) -and (!$Credentials)) { 
        return (Write-Host 'No method selected.' -ForegroundColor Red)
    }


    # Import Fucky64 for Encryption / Decryption
    . $PSScriptRoot/lib/Fucky64-Abridged.ps1

    # Bypass Self-Signed Certificates for Desktop PowerShell
    if ($PSEdition -ne 'Core') { HTTPS-Bypass }  

    # Acquire / Update User Credentials
    $CredObject = User-Creds
    $RootURL = ($CredObject).server
    $Username = ($CredObject).username
    $Password = ($CredObject).password  


    # Prompt for Mandatory Parameters
    if ($Send -eq $TRUE) {
        $ErrorActionPreference = 'SilentlyContinue'
        if (!$Message) { Write-Host 'Enter Message: ' -ForegroundColor Yellow -NoNewline ; $Message = Read-Host }
        if (!$Key) { Write-Host 'Enter Encryption Key: ' -ForegroundColor Yellow -NoNewline ; $Key = ($Key = Read-Host) -as [int] }
        if ((!$TargetUser) -and (!$Check)) { Write-Host 'Enter TargetUser: ' -ForegroundColor Yellow -NoNewline ; $TargetUser = Read-Host }
    }

    # Minor Error Catching
    if ((!$Message) -and ($Send -eq $TRUE)) { return (Write-Host 'Invalid message input.' -ForegroundColor Red) }
    if (($TargetUser -like "*'*") -or ($TargetUser -like "*`"*")) { return (Write-Host 'Invalid user input.' -ForegroundColor Red) }
    $TargetUser = $TargetUser.ToUpper()

    
    if ($Send) { Send-SMS }                 # Send Messages
    elseif ($Retrieve) { Retrieve-SMS }     # Retrieve Messages
    elseif ($Check) { Check-Messages }      # Check Pending Messages

    # Remove Self-Signed Certificate Bypass
    if ($PSEdition -ne 'Core') { HTTPS-Bypass -Undo }
}