@echo off
:: AQUA 通道节点一键安装 (Windows CMD)
:: 用法: curl -fsSL https://tunnel.ltzy.top/join.bat -o join.bat && join.bat
:: 无需管理员，关闭 CMD 窗口仍运行，开机自启

setlocal enabledelayedexpansion
title AQUA 通道节点安装

echo  AQUA 通道节点安装
echo ==============================

set SERVER=tunnel.ltzy.top
set PORT=9999
set TOKEN=YOUR_TUNNEL_TOKEN
set BASE=https://tunnel.ltzy.top
set INSTALL_DIR=%USERPROFILE%\.aqua-tunnel

:: 1. 检测架构
set BIN=tuncli-amd64
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set BIN=tuncli-arm64
if "%PROCESSOR_ARCHITECTURE%"=="x86"   set BIN=tuncli-386
echo 系统: %PROCESSOR_ARCHITECTURE% -^> %BIN%

:: 2. 创建目录
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: 3. 下载二进制
echo 下载 %BASE%/%BIN% ...
curl -fsSL "%BASE%/%BIN%" -o "%INSTALL_DIR%\tuncli.exe" 2>nul
if not exist "%INSTALL_DIR%\tuncli.exe" (
  echo 下载失败，请检查网络
  pause
  exit /b 1
)
echo 下载完成

:: 4. 创建启动脚本 (VBS 实现后台运行，关闭 CMD 不退出)
echo Set WshShell = CreateObject("WScript.Shell") > "%INSTALL_DIR%\run.vbs"
echo WshShell.Run """%INSTALL_DIR%\tuncli.exe"" %SERVER% %PORT% %TOKEN%", 0, False >> "%INSTALL_DIR%\run.vbs"

:: 5. 创建保活批处理
(
echo @echo off
echo :loop
echo echo %%date%% %%time%% 连接 %SERVER%:%PORT% ...
echo cscript //nologo "%INSTALL_DIR%\run.vbs"
echo echo %%date%% %%time%% 断开，3秒后重连
echo timeout /t 3 /nobreak ^>nul
echo goto loop
) > "%INSTALL_DIR%\keepalive.bat"

:: 6. 后台启动（使用 VBS 隐藏窗口）
echo Set WshShell = CreateObject("WScript.Shell") > "%INSTALL_DIR%\start.vbs"
echo WshShell.Run """%INSTALL_DIR%\keepalive.bat""", 0, False >> "%INSTALL_DIR%\start.vbs"
cscript //nologo "%INSTALL_DIR%\start.vbs"
echo 已启动（后台运行，可关闭此窗口）

:: 7. 开机自启（注册表 CurrentVersion\Run，无需管理员）
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AQUATunnel" /t REG_SZ /d "\"%INSTALL_DIR%\start.vbs\"" /f >nul 2>&1
if %errorlevel%==0 (
  echo 开机自启: 已设置
) else (
  echo 开机自启: 设置失败（可能需要手动添加到启动文件夹）
)

echo ==============================
echo  安装完成！通道已就绪
echo  停止: 任务管理器结束 tuncli.exe
echo  卸载: 删除 %INSTALL_DIR% 目录
echo ==============================
pause