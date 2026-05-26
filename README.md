# 华为云盘 WebDAV 服务

基于华为云盘 API 实现的 WebDAV 服务，可将华为云盘映射为本地磁盘，方便使用 WebDAV 客户端进行文件管理。

**参考项目**：[sunshinewithmoonlight/huaweicloud](https://gitee.com/sunshinewithmoonlight/huaweicloud)

## 功能特性

- ✅ WebDAV 协议支持（读、写、删除、移动、重命名）
- ✅ 华为 OAuth 2.0 授权（自动刷新 access_token）
- ✅ 分片上传（单片最大 5MB，支持断点续传）
- ✅ 文件/文件夹操作（列表、下载、上传、删除、移动）
- ✅ 自动缓存路径与元数据，减少 API 调用
- ✅ **Web 管理面板**（用户管理、服务启停、用量查看）
- ✅ **支持 Docker 部署**

## 版本说明

本项目提供两个版本：

| 版本 | 文件 | 特点 | 部署方式 |
|------|------|------|----------|
| **GUI 版（推荐）** | `gui.js` | Web 管理面板 + WebDAV 服务 | Docker / 本地 |
| **CLI 版** | `cli.js` | 纯命令行控制 | 仅本地 |

## 部署方式

### 方式一：Docker 部署（推荐）

使用 `docker-compose.yml` 快速部署：

```yaml
version: '3.8'

services:
  huawei-webdav:
    image: rzdpai/huawei_cloud_webdav:latest
    container_name: huawei-webdav
    restart: unless-stopped
    ports:
      - "1900:1900"
    environment:
      - DAEMON=1
      - PORT=1900
      - DATA_DIR=/data
    volumes:
      - ./data:/data
```

启动服务：

```bash
docker-compose up -d
```

方式二：本地直接运行（GUI 版）

1. 下载文件

```bash
wget https://gh-proxy.org/https://raw.githubusercontent.com/RzdPai/Huawei_Cloud_Webdav/main/gui.js
```

2. 安装依赖

```bash
npm install express express-session body-parser webdav-server
```

3. 启动服务

```bash
node gui.js
```

服务启动后：

· WebDAV 地址：http://localhost:1900
· 管理面板：http://localhost:3000

环境变量

变量 说明 默认值
PORT WebDAV 服务端口 1900
ADMIN_PORT 管理面板端口 3000
ADMIN_PASSWORD 管理面板登录密码 admin123
DEBUG 开启调试日志 0
DAEMON 后台模式运行 0
DATA_DIR 数据存储目录 /data

首次使用

1. 登录管理面板

浏览器访问 http://localhost:3000，输入密码登录（默认 admin123）。

2. 添加华为账号

1. 点击「获取授权码」按钮，跳转华为授权页面
2. 登录华为账号并授权
3. 复制回调地址中的 code= 参数
4. 填写 WebDAV 用户名和密码，粘贴授权码
5. 点击「添加用户」

3. 连接 WebDAV

使用任意 WebDAV 客户端连接：

· 地址：http://localhost:1900
· 用户名：你设置的 WebDAV 用户名
· 密码：你设置的 WebDAV 密码

管理面板功能

· 查看用户列表及华为云盘用量
· 添加/删除 WebDAV 用户
· 手动刷新 Token
· 启动/停止 WebDAV 服务
· 实时查看服务状态

附录：CLI 版本（仅本地）

CLI 版本仅支持本地运行，无管理面板，所有操作通过命令行完成。

1. 下载文件

```bash
wget https://gh-proxy.org/https://raw.githubusercontent.com/RzdPai/Huawei_Cloud_Webdav/main/cli.js
```

2. 安装依赖

```bash
npm install webdav-server
```

3. 运行

```bash
node cli.js
```

CLI 支持的命令：

命令 说明
start 启动 WebDAV 服务
stop 停止 WebDAV 服务
status 查看服务状态和用量
user add 交互式添加用户
user del 删除用户
user list 列出所有用户
exit 退出程序