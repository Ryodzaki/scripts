$services = @(
    @{ Name = "WinDefend";     Type = "Service"  },
    @{ Name = "Bfe";         Type = "Service"   },
    @{ Name = "EventLog";    Type = "Service"  },
    @{ Name = "bam";         Type = "Driver"   },
    @{ Name = "SysMain";     Type = "Service"  },
    @{ Name = "DiagTrack";   Type = "Service"  },
    @{ Name = "Wsearch";     Type = "Service"  },
    @{ Name = "PcaSvc";      Type = "Service"  },
    @{ Name = "DPS";         Type = "Service"  }
)

foreach ($svc in $services) {
    $name = $svc.Name
    $type = $svc.Type

    if ($type -eq "Service") {
        try {
            $service = Get-Service -Name $name -ErrorAction Stop
            if ($service.Status -ne "Running") {
                Write-Host "[$name] Setup StartupType в 'Automatic' and start driver..."
                Set-Service -Name $name -StartupType Automatic
                Start-Service -Name $name
            } else {
                Write-Host "[$name] already working."
            }
        } catch {
            Write-Warning "Service $name not found"
        }
    } elseif ($type -eq "Driver") {   
        $scQuery = sc.exe query $name 2>&1
        if ($scQuery -match "STATE.*STOPPED") {
            Write-Host "[$name] (Driver) Setup StartupType в 'auto' and start driver..."
            sc.exe config $name start= auto | Out-Null
            sc.exe start $name | Out-Null
        } elseif ($scQuery -match "STATE.*RUNNING") {
            Write-Host "[$name] (Driver) already working."
        } else {
            Write-Warning "Driver service $name not found or available."
        }
    }
}