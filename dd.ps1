Invoke-WebRequest -Uri "https://github.com/ZaikoARG/xxstrings/releases/download/1.0.0/xxstrings64.exe" -OutFile "xxstrings64.exe"


$puk = (Get-Process -Name javaw).Id


foreach($smallpuk in $puk)
{
    Write-Host "Analyzing PID: $smallpuk"

    $output = (.\xxstrings64.exe -p $smallpuk | Out-String) -split "`n"
        
    foreach($out in $output) 
    {
        if ($out.Contains("OgUwQPNl"))
        {
            Write-Host "Glam" -ForegroundColor Magenta
        }
    }
}



Remove-Item -Path "xxstrings64.exe" -Force
