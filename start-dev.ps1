# APK-SecAgent 本地开发环境一键启动脚本
# 用法: powershell -ExecutionPolicy Bypass -File start-dev.ps1
$ErrorActionPreference = "Stop"

Write-Host "== APK-SecAgent 本地开发环境启动 ==" -ForegroundColor Cyan

function Resolve-Tool($Name, $FallbackPaths) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in $FallbackPaths) {
        if (Test-Path $p) { return $p }
    }
    throw "未找到 $Name，请先安装并加入 PATH"
}

$PythonExe = Resolve-Tool "python" @()
$UvExe     = Resolve-Tool "uv"     @()
$NodeExe   = Resolve-Tool "node"   @()

Push-Location $PSScriptRoot
try {
    if (-not (Test-Path ".venv")) {
        Write-Host "[..] 创建 Python 虚拟环境并安装依赖"
        & $UvExe venv --python $PythonExe .venv
        & $UvExe pip install --python .venv -r backend\requirements.txt
    }

    if (-not (Test-Path "data\sample\sample-vuln.apk")) {
        Write-Host "[..] 生成测试样本 APK"
        & ".venv\Scripts\python.exe" scripts\generate_sample_apk.py
    }

    Write-Host "[..] 启动后端服务 http://127.0.0.1:8000 (/docs)"
    Start-Process -WorkingDirectory $PSScriptRoot -FilePath ".venv\Scripts\python.exe" `
        -ArgumentList "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000" `
        -WindowStyle Minimized

    Push-Location "$PSScriptRoot\frontend"
    if (-not (Test-Path "node_modules")) {
        Write-Host "[..] 安装前端依赖"
        & npm install --no-audit --no-fund
    }
    Write-Host "[..] 启动前端开发服务 http://localhost:5173"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" -WindowStyle Minimized
    Pop-Location

    Write-Host ""
    Write-Host "== 启动完成 ==" -ForegroundColor Green
    Write-Host "  前端工作台: http://localhost:5173"
    Write-Host "  后端 API:   http://127.0.0.1:8000 (/docs /health)"
    Write-Host "  内置账号:   admin/Admin@12345  analyst/Analyst@12345  viewer/Viewer@12345"
} finally {
    Pop-Location
}
