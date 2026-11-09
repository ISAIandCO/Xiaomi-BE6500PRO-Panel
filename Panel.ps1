param([switch]$Stop)
$ErrorActionPreference = 'Stop'
try {
    $panelScript = Join-Path $PSScriptRoot 'server.mjs'
    if ($Stop) {
        Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
            Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($panelScript, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
            ForEach-Object { Stop-Process -Id $_.ProcessId }
        Write-Host 'Панель остановлена. Настройки роутера сохранены на самом роутере.'
        exit 0
    }
    $panelConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'router-config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $panelAddress = 'http://127.0.0.1:' + [int]$panelConfig.port
    $panelRunning = $false
    try {
        $response = Invoke-WebRequest -Uri $panelAddress -UseBasicParsing -TimeoutSec 2
        $panelRunning = $response.Content.Contains('name="panel-csrf"')
        if (-not $panelRunning) { throw 'Порт занят другим приложением.' }
    } catch [System.Net.WebException] { }
    if (-not $panelRunning) {
        $panelNode = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
        if (-not $panelNode) { throw 'Не найден Node.js. Установите Node.js 22 или новее с https://nodejs.org/ и повторите запуск.' }
        $panelNodeVersion = & $panelNode --version
        if (([version]$panelNodeVersion.TrimStart('v')).Major -lt 22) { throw 'Требуется Node.js 22 или новее.' }
        $panelProcess = Start-Process -FilePath $panelNode -ArgumentList ('"' + $panelScript + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            if ($panelProcess.HasExited) { throw 'Сервер завершился. Проверьте router-config.json или запустите node server.mjs в этой папке.' }
            try {
                $response = Invoke-WebRequest -Uri $panelAddress -UseBasicParsing -TimeoutSec 1
                if ($response.Content.Contains('name="panel-csrf"')) { $panelRunning = $true; break }
            } catch [System.Net.WebException] { }
            Start-Sleep -Milliseconds 200
        }
        if (-not $panelRunning) { throw 'Панель не запустилась. Проверьте доступность локального порта.' }
    }
    Start-Process -FilePath $panelAddress
    Write-Host ('Панель открыта: ' + $panelAddress)
    Write-Host 'Для остановки используйте Stop.cmd.'
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
