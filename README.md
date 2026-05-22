# WeChatMsgExport

微信聊天记录导出工具 — 从 Windows 64位微信 (WeChat v4) 中提取聊天记录并导出为 TXT / HTML。

## 功能

- 自动检测运行中的微信，定位数据库路径
- 提取 SQLCipher 加密密钥（从微信进程内存）
- 解密聊天数据库
- 发现所有聊天会话（联系人 + 群聊）
- 导出为 TXT 或 HTML 格式
- 独立 .exe (12MB)，无需安装 Python

## 快速开始

```bash
# 列出所有会话
WeChatMsgExport.exe list

# 导出指定联系人
WeChatMsgExport.exe export 张三

# 导出全部会话
WeChatMsgExport.exe export-all

# 高级选项
WeChatMsgExport.exe export 张三 -o ./output -f html -n 1000
```

## 从源码运行

```bash
pip install cryptography
python wechat_export.py list
python wechat_export.py export 张三
```

## 打包为 exe

```bash
pip install pyinstaller
pyinstaller --onefile --name WeChatMsgExport --console wechat_export.py
```

## 项目结构

```
wechat_export.py    # CLI 入口
exporter.py         # 会话发现 + TXT/HTML 导出
key_extractor.py    # Windows 内存扫描提取密钥
decryptor.py        # SQLCipher v3 解密
utils.py            # Windows API 封装
```

## 系统要求

- Windows 10/11 64位
- 微信 64位版本 (Weixin v4)
- 微信需处于登录状态
