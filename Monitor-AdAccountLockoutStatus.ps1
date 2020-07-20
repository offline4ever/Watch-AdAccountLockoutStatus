function Monitor-AdAccountLockoutStatus {
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$SamAccountName=$env:username
    )

    #Pruefen, ob das AD-Modul installiert und geladen ist
    if (Get-Module -ListAvailable -Name "ActiveDirectory") {
        Clear-Host;
        
        if (Get-Module -Name "ActiveDirectory") {
            #Modul Installiert und geladen
        } else {
            #Modul installiert
            Import-Module ActiveDirectory
            Write-Host "Das Powershell-Modul 'ActiveDirectory' wurde erfolgreich geladen."
        }

        $clearancemsgsent=$false
        $warningmsgsent=$false

        $name=(Get-ADUser $SamAccountName).Name
        $samaccountname=(Get-ADUser $SamAccountName).samaccountname
        
        Write-Host ((get-date -Format ("yyyy-MM-dd HH:MM:ss")) + " | Überwachung des Accounts '" + $name + "' (" + $samaccountname + ") wird gestartet") -ForegroundColor Yellow
        
        while($true) {
            $lockoutstatus = (Get-ADUser $SamAccountName -Properties LockedOut).lockedout;
            
            if ($lockoutstatus -and -not $warningmsgsent) {
                Write-Host ((get-date -Format ("yyyy-MM-dd HH:MM:ss")) + " | Account '" + $name + "' (" + $samaccountname + ") ist GESPERRT") -ForegroundColor Red
                $warningmsgsent = $true
                $clearancemsgsent = $false
            }

            if (-not $lockoutstatus -and -not $clearancemsgsent) {
                Write-Host ((get-date -Format ("yyyy-MM-dd HH:MM:ss")) + " | Account '" + $name + "' (" + $samaccountname + ") ist NICHT GESPERRT") -ForegroundColor Green
                $warningmsgsent = $false
                $clearancemsgsent = $true
            }

            Start-Sleep -Seconds 5
        }
    } else {
        #Modul nicht installiert
        Throw "Das Powershell-Modul 'ActiveDirectory' ist nicht installiert."
    }
}