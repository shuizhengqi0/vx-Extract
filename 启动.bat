@echo off
chcp 65001 >nul
title WeChatMsgExport - 微信聊天记录导出工具
echo.
echo   ==============================================
echo       WeChatMsgExport - 微信聊天记录导出工具
echo   ==============================================
echo.
echo   可用命令:
echo     list              列出所有聊天会话
echo     export [联系人]    导出指定联系人的聊天记录
echo     export-all        导出全部会话
echo     extract-keys      提取微信数据库密钥
echo     decrypt           解密微信数据库
echo.
echo   示例:
echo     WeChatMsgExport.exe list
echo     WeChatMsgExport.exe export 张三
echo     WeChatMsgExport.exe export-all
echo.
echo   高级选项:
echo     WeChatMsgExport.exe export 张三 -o ./output -f html -n 1000
echo.
echo   ==============================================
echo.

cd /d "%~dp0"
set /p cmd="请输入命令: "
echo.
WeChatMsgExport.exe %cmd%
echo.
pause
