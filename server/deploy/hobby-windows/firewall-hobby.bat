@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion

rem ============================================================
rem 端口来源与后端同源：解析 wgp-node.conf（键与 server.rs 相同），
rem 未写/写 none 的键回退到 07 §6 协议默认值。conf 变了重跑本脚本即可。
rem ============================================================
set "UDP_DHT=11010"
set "UDP_STUN=3478"
set "TCP_SIG=3481"

if exist "wgp-node.conf" (
    for /f "usebackq eol=# tokens=1,* delims==" %%a in ("wgp-node.conf") do (
        set "K=%%a"
        set "V=%%b"
        rem `bind = x` 按等号分词后键带尾随空格，必须先归一再比较
        if defined K set "K=!K: =!"
        if defined V set "V=!V: =!"
        if /i "!K!"=="bind" if defined V set "UDP_DHT=!V:*:=!"
        if /i "!K!"=="stun" set "UDP_STUN=!V!"
        if /i "!K!"=="tcp"  set "TCP_SIG=!V!"
    )
) else (
    echo [提示] 未找到 wgp-node.conf，使用协议默认端口。
)

rem 值为 none 表示该面已关闭，不放行
if /i "!UDP_STUN!"=="none" set "UDP_STUN="
if /i "!TCP_SIG!"=="none"  set "TCP_SIG="

rem 检查管理员权限
net session >nul 2>&1
if errorlevel 1 (
    echo [错误] 需要管理员权限：请右键本脚本，选择“以管理员身份运行”。
    pause
    exit /b 1
)

rem 固定规则名（不含端口）：conf 改端口后重跑本脚本即原位更新，不会堆积旧规则
echo 正在写入 Windows 防火墙入站规则（来源：wgp-node.conf）...
netsh advfirewall firewall delete rule name="wgp-node DHT (UDP)"    >nul 2>&1
netsh advfirewall firewall delete rule name="wgp-node STUN (UDP)"   >nul 2>&1
netsh advfirewall firewall delete rule name="wgp-node Signal (TCP)" >nul 2>&1

netsh advfirewall firewall add rule name="wgp-node DHT (UDP)" dir=in action=allow protocol=UDP localport=!UDP_DHT! profile=any
if defined UDP_STUN netsh advfirewall firewall add rule name="wgp-node STUN (UDP)" dir=in action=allow protocol=UDP localport=!UDP_STUN! profile=any
if defined TCP_SIG  netsh advfirewall firewall add rule name="wgp-node Signal (TCP)" dir=in action=allow protocol=TCP localport=!TCP_SIG! profile=any

echo.
echo 完成。本次放行：
echo   UDP !UDP_DHT!  DHT 信令
if defined UDP_STUN echo   UDP !UDP_STUN!  STUN/观察者
if defined TCP_SIG  echo   TCP !TCP_SIG!  TCP 信令兜底
echo 下一步：在光猫/路由器上把上述端口映射到本机内网 IP（见 README.md）。
pause
