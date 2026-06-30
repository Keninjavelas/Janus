$ErrorActionPreference = 'Stop'

Write-Host '🚧 Building backend...'
go build -o .\bin\janus.exe .\cmd\pq-engine

Write-Host '📦 Installing frontend dependencies...'
Push-Location .\web
npm install
Pop-Location

Write-Host '🛡️ Starting backend...'
$backend = Start-Process -FilePath '.\bin\janus.exe' -NoNewWindow -PassThru

Write-Host '⚡ Starting frontend...'
$webDir = Join-Path -Path $PWD -ChildPath 'web'
$frontend = Start-Process -FilePath 'npm.cmd' -ArgumentList 'run', 'dev' -WorkingDirectory $webDir -NoNewWindow -PassThru

Write-Host '✅ Janus is up! Backend: 8080, Frontend: 5173'
Write-Host 'Press Ctrl+C to stop both processes.'

Wait-Process -Id $backend.Id, $frontend.Id
