# 华为云盘 WebDAV 服务

基于华为云盘 API 实现的 WebDAV 服务，可将华为云盘映射为本地磁盘，方便使用 WebDAV 客户端（如 RaiDrive、Cyberduck）进行文件管理。

**参考项目**：[https://gitee.com/sunshinewithmoonlight/huaweicloud](https://gitee.com/sunshinewithmoonlight/huaweicloud)

## 功能特性

- ✅ WebDAV 协议支持（读、写、删除、移动、重命名）
- ✅ 华为 OAuth 2.0 授权（自动刷新 access_token）
- ✅ 分片上传（单片最大 5MB，支持断点续传）
- ✅ 文件/文件夹操作（列表、下载、上传、删除、移动）
- ✅ 自动缓存路径与元数据，减少 API 调用

## 安装与配置

1. 下载文件

下载webdav.js

2. 安装依赖

```bash
npm install webdav-server
```

3. （可选）修改配置

编辑 webdav.js 开头的配置参数：

```javascript
const WEBDAV_PORT = 1900;          // WebDAV 服务端口
const WEBDAV_USER = 'huawei';      // 登录用户名
const WEBDAV_PASSWORD = 'cloud';   // 登录密码
```

## 首次运行与授权

```bash
node webdav.js
```

首次运行时会提示：

```
请访问以下链接并授权，复制完整回调URL:
https://oauth-login.cloud.huawei.com/oauth2/v3/authorize?response_type=code&...
粘贴URL:
```

· 复制链接到浏览器打开，登录华为账号并授权。
· 授权后，浏览器会重定向到 REDIRECT_URI，复制完整的重定向 URL（包含 ?code=...）。
· 粘贴到终端，程序会自动获取并保存 access_token 到 ACCESS_TOKEN.DATA 文件。
