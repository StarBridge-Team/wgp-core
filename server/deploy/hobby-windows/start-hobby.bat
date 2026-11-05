@echo off
chcp 65001 >nul
title wgp-node-hobby (家庭宽带贡献节点)
cd /d "%~dp0"

echo ============================================
echo  折跃门 wgp-node-hobby 家庭宽带贡献节点
echo  绑定/端口/限频均以 wgp-node.conf 为准
echo  （未写的键用二进制内置默认值，键说明见 conf 内注释）
echo  关闭本窗口或按 Ctrl+C 即停止节点
echo ============================================
echo.

rem 首次部署请先右键“以管理员身份运行”一次 firewall-hobby.bat 放行防火墙，
rem 并在光猫/路由器上完成端口映射（见 README.md，端口以 wgp-node.conf 为准）。

.\wgp-node-hobby.exe %*

echo.
echo [wgp-node-hobby] 节点已退出（退出码 %ERRORLEVEL%）。
pause
