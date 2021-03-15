function SMS-Server {
    Param (
        [switch] $Start,
	[switch] $Stop,
        [switch] $Focus,
	[switch] $SSL,
	[int]    $Port
    )
    
    # Enter server parent directory here.
    $ServerPath = 'C:\Users\<user>\Documents\SMS'
    $SMSServer = ".\sms_server.py"
    $Running = Get-Process -Name python* 2>$NULL

    if ($PSEdition -eq 'Core') { $PowerShell = 'pwsh' }
    else { $PowerShell = 'powershell' }

    if ($Focus) { $Window = 'Normal' }
    else { $Window = 'Minimized' }
    
    $Commands = "-WindowStyle $Window", "-Command Set-Location -LiteralPath '$ServerPath' ; python $SMSServer"
    if ($SSL) { $Commands[-1] += " --ssl" }
    if ($Port) { $Commands[-1] += " --port $Port" }
 
    if ($Start) {
        if (!$Running) { Start-Process -FilePath $PowerShell -ArgumentList $Commands ; Write-Host 'Server started.' -ForegroundColor Green }
        else { Write-Host 'Server already running.' -ForegroundColor Green }
    }

    elseif ($Stop) {
        if ($Running) { Stop-Process -Name python* ; Write-Host 'Server stopped.' -ForegroundColor Red }
        else { Write-Host 'Server already stopped.' -ForegroundColor Red }
    }

    else { Write-Host 'No action specified.' -ForegroundColor Red }
}