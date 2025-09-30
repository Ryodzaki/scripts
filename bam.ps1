$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (NotSigned)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (HashMismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (NotTrusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (UnknownError)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}

Clear-Host

Write-Host "BAM Parser - Command Line Output"
Write-Host "by glam"

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 3
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    Try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    }
    Catch {
        Write-Warning "Error Mounting HKEY_Local_Machine"
    }
}

$bv = ("bam", "bam\State")
Try {
    $Users = foreach($ii in $bv) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
}
Catch {
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

# Собираем данные
$Bam = Foreach ($Sid in $Users) {
    foreach($rp in $rpath) {
        Write-Host -ForegroundColor Yellow "Processing SID: $Sid in $rp"
        
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        
        Try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]) 
            $User = $User.Value
        }
        Catch {
            $User = "Unknown"
        }
        
        ForEach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
    
            If($key.length -eq 24) {
                $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
                $Biasd = $Bias/60
                $Dayd = $Day/60
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
                
                $d = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    ((split-path -path $item).Remove(23)).trimstart("\Device\HarddiskVolume")
                } else {
                    $d = ""
                }
                
                $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Split-path -leaf ($item).TrimStart()
                } else {
                    $item
                }
                
                $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    ($item).Remove(1,23)
                } else {
                    $cp = ""
                }
                
                $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Join-Path -Path "C:" -ChildPath $cp
                } else {
                    $path = ""
                }
                
                $sig = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Get-Signature -FilePath $path
                } else {
                    $sig = "N/A (Non-file path)"
                }
                
                [PSCustomObject]@{
                    'Last Execution Time (UTC)' = $TimeUTC
                    'Application' = $f
                    'Path' = $path
                    'Signature' = $sig
                    'User' = $User
                    'SID' = $Sid
                }
            }
        }
    }
}

# Вывод результатов в CLI формате
if ($Bam) {
    Write-Host "`nBAM Key Entries ($($Bam.Count))" -ForegroundColor Green
    Write-Host "User TimeZone: $UserTime, ActiveBias: $Bias, DayLightTime: $Day`n" -ForegroundColor Cyan
    
    # Форматируем вывод как таблицу с цветовой маркировкой подписей
    $Bam | ForEach-Object {
        $color = if ($_.Signature -eq "Valid Signature") {
            "Green"
        } elseif ($_.Signature -like "Invalid Signature*") {
            "Red"
        } elseif ($_.Signature -eq "File Was Not Found") {
            "Yellow"
        } else {
            "White"
        }
        
        [PSCustomObject]@{
            'Last Execution Time (UTC)' = $_.'Last Execution Time (UTC)'
            'Application' = $_.Application
            'Signature' = $_.Signature
        } | Format-Table -AutoSize | Out-String | ForEach-Object {
            $lines = $_ -split "`r`n"
            foreach ($line in $lines) {
                if ($line -match $_.Signature) {
                    Write-Host $line -ForegroundColor $color
                } else {
                    Write-Host $line
                }
            }
        }
    }
    
    # Дополнительная статистика
    Write-Host "`nStatistics:" -ForegroundColor Green
    Write-Host "Total entries: $($Bam.Count)"
    
    $uniqueUsers = $Bam | Group-Object User | ForEach-Object {
        "$($_.Name): $($_.Count) entries"
    }
    Write-Host "Users found: $($uniqueUsers -join ', ')"
    
    $validSignatures = ($Bam | Where-Object {$_.Signature -eq "Valid Signature"}).Count
    $invalidSignatures = ($Bam | Where-Object {$_.Signature -like "Invalid Signature*"}).Count
    $notFound = ($Bam | Where-Object {$_.Signature -eq "File Was Not Found"}).Count
    $na = ($Bam | Where-Object {$_.Signature -eq "N/A (Non-file path)"}).Count
    
    Write-Host "Files with valid signatures: $validSignatures" -ForegroundColor Green
    Write-Host "Files with invalid signatures: $invalidSignatures" -ForegroundColor Red
    Write-Host "Files not found: $notFound" -ForegroundColor Yellow
    Write-Host "Non-file paths: $na"
    
} else {
    Write-Host "No BAM entries found." -ForegroundColor Red
}

$sw.Stop()
Write-Host "`nElapsed Time: $($sw.Elapsed.ToString('mm\:ss')) minutes" -ForegroundColor Yellow

# Опция сохранения результатов в CSV
$saveToCsv = Read-Host "`nDo you want to save results to CSV? (y/n)"
if ($saveToCsv -eq 'y' -or $saveToCsv -eq 'Y') {
    $csvPath = Read-Host "Enter path for CSV file (default: $pwd\BAM_Results.csv)"
    if ([string]::IsNullOrEmpty($csvPath)) {
        $csvPath = "$pwd\BAM_Results.csv"
    }
    $Bam | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results saved to: $csvPath" -ForegroundColor Green
}