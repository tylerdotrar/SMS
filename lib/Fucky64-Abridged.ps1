<###
Convoluted integer-based key encryption / decryption of strings and files.
ARBITRARY VERSION NUMBER:  [ABRIDGED]
AUTHOR:  Tyler McCann (@tyler.rar)

For full version visit link https://github.com/tylerdotrar/Fucky64
###>

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