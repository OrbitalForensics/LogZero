$env:GO111MODULE = "on"
$env:GOPATH = "$env:USERPROFILE\go"
Set-Location "C:\Projects\LogZero"
wails build
