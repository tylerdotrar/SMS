function SMS-Client {
#.SYNOPSIS
# Volatile dual encryption messaging system.
# ARBITRARY VERSION NUMBER:  0.6.9-1
# AUTHOR:  Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# Volatile double-encrypted CLI messaging system that works natively on Windows, while also working on Linux when
# using PowerShell Core.  Messages are encoded OR encrypted (if a user decides to input a key) client-side
# utilizing a custom, convoluted text encryption algorithmare before being sent to the SMS server over http or
# https (preferred).  On the server, the messages are held in memory until the recipient authenticates and pulls
# the message, or until the server is shut down; at no point are messages written to disk.
#
# Notes:
# - Current build doesn't support domain names; utilizes regex for protocols, IPs, and ports. Will fix soon.
# - Main goal is to add a more secure third layer of encryption, as well as a Python client for seemless OS utility.
# - Longterm goal is to upgrade to a robust, volatile conversation system rather than individual messages.
#
# Parameters:
#    -Send                     -->   Send message.
#    -Retrieve                 -->   Retrieve message (if one is pending).
#    -Credentials              -->   Create/modify SMS user credentials in 'credentials.ini'.
#    -Message                  -->   (Optional) Enter SMS message.
#    -Key                      -->   (Optional) Enter numerical key to encrypt SMS message.
#    -TargetUser               -->   (Optional) Enter SMS message recipient.
#    -Check                    -->   (Debug) Return quantity of pending messages.
#    -Raw                      -->   (Debug) Return pending message data fields.
#    -Help                     -->   Return Get-Help page.
#    -CheckOnTerminalLaunch    -->   (WIP) Toggle message check in a banner on every terminal launch.
#    
# Example Usage:
#    []  PS C:\Users\Bobby> 
#
#.LINK
# https://github.com/tylerdotrar/SMS

    [Alias('SMS')]

    Param (
        [switch] $Send,
        [switch] $Retrieve,
        [switch] $Credentials,
        [string] $Message,
        [int]    $Key,
        [string] $TargetUser,
        [switch] $Check,
        [switch] $Raw,
        [switch] $Help,
        [switch] $CheckOnTerminalLaunch
    )


    # Main Functions
    function Send-SMS {
        
        # Prompt for Message, PIN, and Recipient
        $ErrorActionPreference = 'SilentlyContinue'
        if (!$Message)    { Write-Host 'Enter Message: ' -ForegroundColor Yellow -NoNewline ; $Message = Read-Host }
        if (!$Key)        { Write-Host 'Enter Encryption Key: ' -ForegroundColor Yellow -NoNewline ; $Key = ($Key = Read-Host) -as [int] }
        if (!$TargetUser) { Write-Host 'Enter TargetUser: ' -ForegroundColor Yellow -NoNewline ; $TargetUser = (Read-Host).ToUpper() }


        # Establish JSON Fields
        if ($Key) { $Encrypted = $TRUE  }
        else      { $Encrypted = $FALSE }


        # Encode/Encrypt Message Prior to Submission
        $EncMessage = Fucky64-Encrypt
        

        # Generate Timestamp
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


        $Client.UploadString("$RootURL/send", $Body)

    }
    function Retrieve-SMS {

        # Retrieve Encoded / Encrypted Message

        [pscustomobject]$Body = @{
            'targetUser'    = $Username
            'password'      = $Password
        } | ConvertTo-Json



        #### BROKEN. NEED TO OVERHUAL SMS_SERVER.PY AND IMPLEMENT COOKIE SYSTEM. ####
        #$Response = $Client.UploadString("$RootURL/retrieve", $Body)
         
        
        # Didn't want to include this, but I'll leave it until I implement the cookie login system to improve security and WebClient functionality.
        if ($PSEdition -eq 'Core') { $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $Body -Method GET).content }
        else { $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -ContentType "application/json; charset=utf-8" -Body $Body -Method GET).content }
        

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

        # Create a Web Client to communicate with the server.
        $Client = [System.Net.WebCLient]::new()
        $Response = $Client.DownloadString("$RootURL/master")


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
    function User-Credentials ([switch]$Generate, [switch]$Retrieve) {
        
        # Quick Base64 function to encode/decode user credentials.
        function Base64 ([switch]$Encode,[switch]$Decode,[string]$Message) {
    
            if ($Encode)     { $Output = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Message))    }
            elseif ($Decode) { $Output = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Message)) }
            return $Output
        }
        

        # Return info from 'credentials.ini' instead of generating credentials.
        if ($Retrieve) {
            
            $EncodedCredentials = Get-Content -LiteralPath $CredentialFile | ConvertFrom-Json
            $RootURL            = Base64 -Decode $EncodedCredentials.server
            $Username           = Base64 -Decode $EncodedCredentials.username
            $Password           = Base64 -Decode $EncodedCredentials.password

            return @{server=$RootURL; username=$Username; password=$Password}
        }


        # Create / Modify User Credentials
        elseif ($Generate) {
            
            Write-Host "╔═════════════╗`n║" -NoNewline
            Write-Host ' Credentials ' -NoNewline -ForegroundColor Yellow
            Write-Host "║`n╚═════════════╝"

            #Write-Host 'CREDENTIAL CREATION' -ForegroundColor Red

            # Username Input
            while ($TRUE) {
                Write-Host 'Username: ' -ForegroundColor Yellow -NoNewline ; $CredUser = Read-Host
                if (($CredUser -like "*'*") -or ($CredUser -like "*`"*")) { Write-Host 'Invalid user input.' -ForegroundColor Red }
                else { break }
            }


            # Password Input
            while ($TRUE) {
                Write-Host 'Password: ' -ForegroundColor Yellow -NoNewLine ; $CredPass = Read-Host
                if ($CredPass -like "* *") { Write-Host 'Invalid user input.' -ForegroundColor Red }
                else { break }
            }


            # Server Input (Currently only supports
            $IPRegex = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'
            while ($TRUE) {
                Write-Host 'Server URL: ' -ForegroundColor Yellow -NoNewline ; $RootURL = Read-Host

                # Verify server is reachable
                if ((($RootURL -match 'http://') -or ($RootURL -match 'https://')) -and ($RootURL -match $IPRegex)) {
                    
                    $ServerIP = $Matches[0]
                    $ServerPort = $RootURL.Split(':')[-1]

                    # Added to fix Linux compatibility
                    if ($isLinux) { $Results = $TRUE }
                
                    else { $Results = (Test-NetConnection -RemoteAddress $ServerIP -Port $ServerPort).TCPTestSucceeded }

                    if ($Results) { break }
                }

                else { Write-Host 'Invalid user input.' -ForegroundColor Red }
            }


            # Encode Credentials & Create 'credentials.ini'
            $EncodedURL      = Base64 -Encode $RootURL
            $EncodedUsername = Base64 -Encode $CredUser.ToUpper()
            $EncodedPassword = Base64 -Encode $CredPass

            $EncodedCredentials = @{server=$EncodedURL; username=$EncodedUsername; password=$EncodedPassword} | ConvertTo-Json
            New-Item -Path $CredentialFile -Value $EncodedCredentials -Force | Out-Null
            
            
            # Create/Update User on SMS Server
            $ServerCredObject = @{username=$CredUser.ToUpper(); password=$CredPass} | ConvertTo-Json
            

            # Determine if SMS server URL is http or https to enable HTTPS self-signed certicate bypass.
            $Protocol   = $RootURL.Split(':')[0]
            if ($Protocol -eq 'https') { HTTPS-Bypass }

            
            # Create WebClient to communicate with SMS server.
            $Client = [System.Net.WebClient]::new()
            $Client.Headers.Add("Content-Type","application/json")
            $Client.UploadString("$RootURL/update", $ServerCredObject)

            
            # Remove Self-Signed Certificate Bypass
            if ($Protocol -eq 'https') { HTTPS-Bypass -Undo }
        }
    }
    function HTTPS-Bypass ([switch]$Undo) {
    
        ### Self-Signed Certificate / HTTPS Bypass ###

        # Remove Certificate Bypass at the end of Script
        if ($Undo) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $NULL }


        # This C# code bypasses the certificate check for [System.Net.WebClient] in both .NET and .NET Core; useful for HTTPS communication without a valid SSL certificate.
        $CertBypass = @'
using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace SelfSignedCerts
{
    public class UploadBypass
    {
         public static Func<HttpRequestMessage,X509Certificate2,X509Chain,SslPolicyErrors,Boolean> ValidationCallback = 
            (message, cert, chain, errors) => {
                return true; 
            };
    };
    public class PowerShellCertificates
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
}
'@

        if ($PSEdition -eq 'Core') { Add-Type $CertBypass }
        else { Add-Type -AssemblyName System.Net.Http ; Add-Type $CertBypass -ReferencedAssemblies System.Net.Http }

        # Invoke certificate bypass for both Windows PowerShell and Core
        [SelfSignedCerts.PowerShellCertificates]::Bypass()
    }


    # Return Help Page
    if ($Help) { return (Get-Help SMS) }


    # Return if No Primary Parameter Selected
    if ((!$Send) -and (!$Retrieve) -and (!$Check) -and (!$Credentials)) { 
        return (Write-Host 'No method selected.' -ForegroundColor Red)
    }


    # Return if code was loaded into Terminal w/o actual .ps1 file.  Will implement this functionality later.
    if (!$PSScriptRoot) { return (Write-Host 'Client missing dependencies.' -ForegroundColor Red) }


    # Create/Modify User Credentials
    $CredentialFile = "$PSScriptRoot\var\credentials.ini"
    if ($Credentials) { User-Credentials -Generate ; return }
    
    # Ugly error catching if credentials.ini doesn't exist and/or isn't proper JSON.
    elseif (!(Get-Content -LiteralPath $CredentialFile -ErrorAction SilentlyContinue | ConvertFrom-Json 2>$NULL )) {
        return (Write-Host 'Must generate valid credentials.' -ForegroundColor Red)
    }
    

    # Acquire User Credentials
    $CredObject = User-Credentials -Retrieve
    $RootURL    = $CredObject.server
    $Username   = $CredObject.username
    $Password   = $CredObject.password


    # Determine if SMS server URL is http or https to enable HTTPS self-signed certicate bypass.
    $Protocol   = $RootURL.Split(':')[0]
    if ($Protocol -eq 'https') { HTTPS-Bypass }

            
    # Create WebClient for communication with SMS server.
    $Client = [System.Net.WebClient]::new()
    $Client.Headers.Add("Content-Type","application/json")
    

    #### NEED TO IMPLEMENT COOKIE SYSTEM FROM P2.FILETRANSFER ####


    # Import Fucky64 for Encryption / Decryption
    . $PSScriptRoot/lib/Fucky64-Abridged.ps1

    
    # Main Functionality
    if ($Send)         { Send-SMS       }
    elseif ($Retrieve) { Retrieve-SMS   }
    elseif ($Check)    { Check-Messages }


    # Remove Self-Signed Certificate Bypass
    if ($Protocol -eq 'https') { HTTPS-Bypass -Undo }
}