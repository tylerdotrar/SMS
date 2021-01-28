function SecureMessagingSystem {
    
    [Alias('SMS')]

    Param (
        [string] $Message,
        [int]    $Key,
        [uri]    $RootURL = '<url>',
        [string] $TargetUser,
        [switch] $Send,
        [switch] $Retrieve,
        [switch] $Check,
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
        $Body = "{`"message`":`"$EncMessage`", `"encrypted`":`"$Encrypted`", `"targetUser`":`"$TargetUser`", `"timestamp`":`"$Timestamp`", `"uid`":`"seventeenthirtyeight`"}"
        (Invoke-WebRequest -Uri "$RootURL/send" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $Body -Method POST).content
    }
    function Retrieve-SMS {

        # Retrieve Encoded / Encrypted Message
        $Body = "{`"targetUser`":`"$TargetUser`", `"uid`":`"seventeenthirtyeight`"}"
        $Response = (Invoke-WebRequest -Uri "$RootURL/retrieve" -SkipCertificateCheck -ContentType "application/json; charset=utf-8" -Body $Body -Method GET).content

        try {

            # Parse JSON Fields
            $Encrypted = ($Response | ConvertFrom-Json).encrypted
            $Timestamp = ($Response | ConvertFrom-Json).timestamp
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

    # Encryption / Decryption
    function Fucky64-Encrypt {

        ### THIS IS THE ABRIDGED VERSION ###
        $ErrorActionPreference = 'SilentlyContinue'

        # Convert message contents to base64 and modify output
	    $64text = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($Message))
	    $ModifiedText = $64text.replace("A","+").replace("B","-").replace("=","!")

        # Segregate modified base64 into even and odd character arrays and append into a string
	    $EvenArray = @()
	    $OddArray = @()
        
        for ($CharIndex = 0; $CharIndex -lt $ModifiedText.Length; $CharIndex += 2) {
            
            $OddArray += $ModifiedText[$CharIndex]
            $EvenArray += $ModifiedText[$CharIndex + 1]
        }
        
        $Segregated = ($EvenArray + $OddArray) -join ""

        # Convert segregated string to hexadecimal strings (spaced and conjoined)
	    $HexArray = @()

        for ($CharIndex = 0; $CharIndex -lt $Segregated.Length; $CharIndex++) {
            $HexArray += [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($Segregated[$CharIndex]))
	    }

        $SpacedHex = $HexArray -join " "
        $JoinedHex = $SpacedHex -replace " ",""

        ### Encoding and encryption split into different processes ###

        # Start Encryption Process
        if ($Key) {
            
            # Create ASCII strings (spaced and conjoined)
            $SpacedASCII = [byte[]][char[]]$JoinedHex
            $JoinedASCII = $SpacedASCII -join ""

            # Create 8 character ASCII substrings
            $ASCIIarray = @()

            for ($CharIndex = 0; $CharIndex -lt $JoinedASCII.Length; $CharIndex += 8) {
                $ASCIIarray += $JoinedASCII[$CharIndex..($CharIndex+7)] -join ""
            }
            
            # Divide each substring by the key and segregate into even and odd arrays.
            $FuckyPreFlip = @()

            foreach ($Substring in $ASCIIarray) { $FuckyPreFlip += $Substring / $Key }

	        $FinalEvenArray = @()
	        $FinalOddArray = @()
            
            for ($SubstringIndex = 0; $SubstringIndex -lt $FuckyPreFlip.Count; $SubstringIndex += 2) {
            
                $FinalOddArray += $FuckyPreFlip[$SubstringIndex]
                $FinalEvenArray += $FuckyPreFlip[$SubstringIndex + 1]
            }

            $FinalFlippedArray = $FinalEvenArray + $FinalOddArray

            # Generate random alphabetical delimiter and create final message
            $Delim = (65..90) | Get-Random | % { [char]$_ }
            $EncryptedMsg = $FinalFlippedArray -join "$Delim"
        }

        # Start Encoding Process
        else {
            
            # Convert conjoined hexadecimal string to second base64 and modify output
	        $64ception = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($JoinedHex))
	        $Modified64ception = $64ception.replace("A","+").replace("B","-").replace("=","!")
            
            # Create second even and odd array mix and create final message
	        $FinalEvenArray = @()
	        $FinalOddArray = @()
            
            for ($CharIndex = 0; $CharIndex -lt $Modified64ception.Length; $CharIndex += 2) {
            
                $FinalOddArray += $Modified64ception[$CharIndex]
                $FinalEvenArray += $Modified64ception[$CharIndex + 1]
            }

            $EncodedMsg = ($FinalEvenArray + $FinalOddArray) -join ""
        }

        # Return Message
        if ($Key) { return $EncryptedMsg }
        else { return $EncodedMsg } 
    }
    function Fucky64-Decrypt {

        ### THIS IS THE ABRIDGED VERSION ###
        $ErrorActionPreference = 'SilentlyContinue'

        # Start Decryption Process
        if ($Key) {

            $EncryptedMsg = $EncMessage
            
            # Remove alphabet delimiters from encrypted message and create array (segregated key-divided ASCII pieces)
            $NoAlphabet = $EncryptedMsg -Replace "[A-Z]", " "
            $KeyedSegments = $NoAlphabet.split(" ")

            # Create even and odd (key-divided ASCII) substring array and create unsegregated (aka original order) array
            $KeyEvenArray = @()
            $KeyOddArray = @()
            $FuckyPreFlip = @()

            for ($Substring = 0; $Substring -lt $KeyedSegments.Count; $Substring++ ) {

                if ($Substring -lt ($KeyedSegments.Count / 2) ) { $KeyEvenArray += $KeyedSegments[$Substring] }
                else { $KeyOddArray += $KeyedSegments[$Substring] }
            }

            for ($Substring = 0; $Substring -lt $KeyedSegments.count; $Substring++) {

                $FuckyPreFlip += $KeyOddArray[$Substring]
                $FuckyPreFlip += $KeyEvenArray[$Substring]
            }

            # Multiply each keyed ASCII substring by the key to get original ASCII string
            $DekeyedASCII = @()

            for ($Substring = 0; $Substring -lt $KeyedSegments.count; $Substring++) {

                $KeyedSubstring = [double]$FuckyPreFlip[$Substring]
                $DekeyedSubstring = $KeyedSubstring * $Key

                $TinyFix = [math]::Round($DekeyedSubstring)
                $DekeyedASCII += $TinyFix
            }
            
            $JoinedASCII = $DekeyedASCII -join ""

            # Convert ASCII to conjoined hexadecimal string
            $JoinedHex = @()

            for ($ASCIIchar = 0; $ASCIIchar -lt $JoinedASCII.Length; $ASCIIchar += 2) {
                
                $ASCIIbyte = $JoinedAscii[$ASCIIchar..($ASCIIchar+1)] -join ""
                $HexCharacter = [char[]][byte[]]$ASCIIbyte
                $JoinedHex += $HexCharacter
            }

            $JoinedHex = $JoinedHex -join ""
        }

        # Start Decoding Process
        else {

            $EncodedMsg = $EncMessage

            # Spit encoded message in half (creating even and odd character arrays)
	        $EvenArray = @()
	        $OddArray = @()

            for ($CharIndex = 0; $CharIndex -lt $EncodedMsg.Length; $CharIndex++) {

                if ($CharIndex -lt ($EncodedMsg.Length / 2) ) { $EvenArray += $EncodedMsg[$CharIndex] }
                else { $OddArray += $EncodedMsg[$CharIndex] }
            }

            # Create unsegregated modified base64 message (Original Order)
            $Modified64ception = @()

            for ($Index = 0; $Index -lt $EncodedMsg.Length; $Index++) {

                $Modified64ception += $OddArray[$Index]
                $Modified64ception += $EvenArray[$Index]
            }

            $Modified64ception = $Modified64ception -join ""

            # Unmodify base64 and convert to hexadecimal
            $64ception = $Modified64ception.replace("+","A").replace("-","B").replace("!","=")
            $JoinedHex = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($64ception))
        }

        ### Decoding and decryption converge into the same process ###

        # Split conjoined hexadecimal string into separated hex bytes
        $SpacedHex = @()

        for ($HexIndex = 0; $HexIndex -lt $JoinedHex.Length; $HexIndex += 2) {
            $SpacedHex += $JoinedHex[$HexIndex..($HexIndex+1)] -join ""
        }

        $SpacedHex = $SpacedHex -join " "

        # Convert hexadecimal bytes back into segregated modified base64
        $Segregated = $SpacedHex -split ' ' | % {[char][byte]"0x$_"}
        $Segregated = $Segregated -join ""

        # Split segregated modified base64 array in half (creating even and odd arrays)
        $FinalEvenArray = @()
        $FinalOddArray = @()

        for ($CharIndex = 0; $CharIndex -lt $Segregated.Length; $CharIndex++) {

            if ($CharIndex -lt ($Segregated.Length / 2) ) { $FinalEvenArray += $Segregated[$CharIndex] }
            else { $FinalOddArray += $Segregated[$CharIndex] }
        }

        # Create unsegregated modified base64 string (Original Order)
        $ModifiedText = @()

        for ($Index = 0; $Index -lt $Segregated.Length; $Index++) {

            $ModifiedText += $FinalOddArray[$Index]
            $ModifiedText += $FinalEvenarray[$Index]
        }

        $ModifiedText = $ModifiedText -join ""

        # Unmodify to original base64 and convert to original message
        $64text = $ModifiedText.replace("+","A").replace("-","B").replace("!","=")
        $Cleartext = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($64text))

        # If message isn't cleartext OR initial hex string not valid characters, decryption failed
        if (!$Cleartext -or ($JoinedHex -notmatch '^[A-Z0-9]+$')) {

            if ($Key) { Write-Host "Incorrect key." -ForegroundColor Red }
            else { Write-Host "No key entered." -ForegroundColor Red }

            return
        }

        # Only return decrypted / decoded message contents.
        return $Cleartext
    }

    # Exit
    if (($Send -eq $FALSE) -and ($Retrieve -eq $FALSE) -and ($Check -eq $FALSE)) { 
        return (Write-Host 'No method selected.' -ForegroundColor Red)
    }

    # Prompt for Mandatory Parameters
    if ((!$Message) -and ($Send -eq $TRUE)) { Write-Host 'Enter Message: ' -ForegroundColor Yellow -NoNewline ; $Message = Read-Host }
    if ((!$Key) -and ($Send -eq $TRUE)) { Write-Host 'Enter Encryption Key: ' -ForegroundColor Yellow -NoNewline ; $Key = Read-Host }
    if ((!$TargetUser) -and (!$Check)) { Write-Host 'Enter TargetUser: ' -ForegroundColor Yellow -NoNewline ; $TargetUser = Read-Host }
    if ($RootURL -eq '<url>') { Write-Host 'Enter Server URL: ' -ForegroundColor Yellow -NoNewline ; $RootURL = Read-Host }


    # Minor error catching
    if ((!$Message) -and ($Send -eq $TRUE)) { return (Write-Host 'Invalid message input.' -ForegroundColor Red) }
    if (($TargetUser -like "'") -or ($TargetUser -like "`"")) { return (Write-Host 'Invalid user input.' -ForegroundColor Red) }
    $TargetUser = $TargetUser.ToUpper()

    
    if ($Send) { Send-SMS }          ### Send Messages
    if ($Retrieve) { Retrieve-SMS }  ### Retrieve Messages
    if ($Check) { Check-Messages }   ### Check Pending Messages
}