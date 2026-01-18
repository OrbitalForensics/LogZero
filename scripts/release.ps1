# LogZero Release Script (PowerShell)
# Usage: .\scripts\release.ps1 -Version v1.0.0

param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

# Validate version format
if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    Write-Error "Error: Version must be in format v1.0.0"
    exit 1
}

$VersionNum = $Version -replace '^v', ''

Write-Host "Releasing LogZero $Version" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Update version in wails.json
Write-Host "Updating version in wails.json..."
$wailsJson = Get-Content "wails.json" -Raw | ConvertFrom-Json
$wailsJson.info.productVersion = $VersionNum
$wailsJson | ConvertTo-Json -Depth 10 | Set-Content "wails.json"

# Commit version bump
Write-Host "Committing version bump..."
git add wails.json
git commit -m "Bump version to $Version" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "No changes to commit" -ForegroundColor Yellow
}

# Create and push tag
Write-Host "Creating tag $Version..."
git tag -a $Version -m "Release $Version"

Write-Host "Pushing to remote..."
git push origin main
git push origin $Version

Write-Host ""
Write-Host "Release $Version triggered!" -ForegroundColor Green
Write-Host "GitHub Actions will now build installers for all platforms."
Write-Host "Check progress at: https://github.com/OrbitalForensics/LogZero/actions" -ForegroundColor Blue
Write-Host ""
Write-Host "Once complete, the release will be available at:"
Write-Host "https://github.com/OrbitalForensics/LogZero/releases/tag/$Version" -ForegroundColor Blue
