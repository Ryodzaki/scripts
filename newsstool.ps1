$videoUrl = "https://raw.githubusercontent.com/Ryodzaki/scripts/refs/heads/main/rigalovo.mp4"
$output = "$env:TEMP\video.mp4"
 
Invoke-WebRequest -Uri $videoUrl -OutFile $output
 
Add-Type -AssemblyName PresentationFramework
 
$window = New-Object Windows.Window
$mediaElement = New-Object Windows.Controls.MediaElement
$mediaElement.Source = [Uri]$output
$mediaElement.LoadedBehavior = "Play"
$window.Content = $mediaElement
$window.Width = 576
$window.Height = 1152
$window.Title = "Видео"
$mediaElement.Add_MediaEnded({
    $window.Close()
    Remove-Item $output -ErrorAction SilentlyContinue
})
$window.ShowDialog() | Out-Null
