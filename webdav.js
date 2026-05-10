// ==================== 配置参数 ====================
// WebDAV 服务监听端口
const WEBDAV_PORT = 1900;
// WebDAV 登录用户名
const WEBDAV_USER = 'huawei';
// WebDAV 登录密码
const WEBDAV_PASSWORD = 'cloud';
// 上传/下载时忽略的文件名列表（不处理这些文件）
const SKIP_FILES = ['.DS_Store'];

// 华为OAuth客户端ID
const CLIENT_ID = '116330451';
// 华为OAuth客户端密钥
const CLIENT_SECRET = '1c67650714343f0c661f9ed760acce4a337a3c36f08bce95166920f9a375b6b9';
// OAuth回调地址
const REDIRECT_URI = 'https://gitee.com/sunshinewithmoonlight/huaweicloud';
// 请求的权限范围（多个 scope 用 + 连接）
const SCOPE = 'openid+profile+https://www.huawei.com/auth/drive+https://www.huawei.com/auth/drive.file';
// 华为 OAuth 授权地址（拼接好的完整 URL）
const AUTHORIZE_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/authorize?'
    + 'response_type=code&access_type=offline&state=webdav_huawei'
    + '&client_id=' + CLIENT_ID
    + '&redirect_uri=' + REDIRECT_URI
    + '&scope=' + SCOPE;

// 单次分片上传的最大大小（5MB）
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024;
// 本地存储 access_token 的文件名
const TOKEN_FILE = 'ACCESS_TOKEN.DATA';
// ==================== 配置参数 ====================

const FS = require('fs');
const PATH = require('path');
const HTTPS = require('https');
const QS = require('querystring');
const READLINE = require('readline');
const OS = require('os');
const { Readable, Writable } = require('stream');
const webdav = require('webdav-server').v2;

const ERR_NOT_FOUND = webdav.Errors.ResourceNotFound;

let ACCESS_TOKEN = '';
let REFRESH_TOKEN = '';
let refreshingToken = null;
let ROOT_ID = null;

function getMimeType(fileName) {
    const ext = PATH.extname(fileName).toLowerCase();
    const MIMETYPES = {
        '.apk': 'application/vnd.android.package-archive',
        '.mp4': 'video/mp4', '.mkv': 'video/x-matroska', '.avi': 'video/x-msvideo',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif',
        '.txt': 'text/plain', '.js': 'application/x-javascript', '.json': 'application/json',
        '.pdf': 'application/pdf', '.zip': 'application/zip', '.rar': 'application/x-rar-compressed'
    };
    return MIMETYPES[ext] || 'application/octet-stream';
}

function safeJsonParse(data, ctx = '') {
    try {
        return { success: true, data: JSON.parse(data) };
    } catch (e) {
        console.error(`JSON解析失败 ${ctx}:`, data?.substring(0, 200));
        return { success: false, error: e };
    }
}

function httpsRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
        const req = HTTPS.request(options, (res) => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, raw: Buffer.concat(chunks).toString('utf8') }));
            res.on('error', reject);
        });
        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

async function refreshToken() {
    if (refreshingToken) return refreshingToken;
    refreshingToken = (async () => {
        try {
            const postData = QS.stringify({
                grant_type: 'refresh_token',
                refresh_token: REFRESH_TOKEN,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET
            });
            const options = {
                hostname: 'oauth-login.cloud.huawei.com',
                port: 443,
                path: '/oauth2/v3/token',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData, 'utf8')
                }
            };
            const { raw } = await httpsRequest(options, postData);
            const result = safeJsonParse(raw, '刷新token');
            if (!result.success || result.data.error) throw new Error('刷新token失败');
            const newData = result.data;
            if (!newData.refresh_token) newData.refresh_token = REFRESH_TOKEN;
            FS.writeFileSync(TOKEN_FILE, JSON.stringify(newData));
            ACCESS_TOKEN = newData.access_token;
            REFRESH_TOKEN = newData.refresh_token;
            console.log('Token已刷新');
        } catch (e) {
            console.error('Token刷新失败', e);
            throw e;
        } finally {
            refreshingToken = null;
        }
    })();
    return refreshingToken;
}

async function authorize() {
    console.log('请访问以下链接并授权，复制完整回调URL:\n', AUTHORIZE_URL);
    const rl = READLINE.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise(resolve => rl.question('粘贴URL: ', resolve));
    rl.close();

    const match = answer.match(/[?&#]code=([^&]+)/);
    const code = match ? match[1] : null;

    if (!code) throw new Error('未获取到授权码');

    const postData = QS.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI
    });
    const options = {
        hostname: 'oauth-login.cloud.huawei.com',
        port: 443,
        path: '/oauth2/v3/token',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData, 'utf8')
        }
    };
    const { raw } = await httpsRequest(options, postData);
    const result = safeJsonParse(raw, '换取token');
    if (!result.success || result.data.error) throw new Error('授权失败');
    FS.writeFileSync(TOKEN_FILE, raw);
    return result.data;
}

async function initToken() {
    if (FS.existsSync(TOKEN_FILE)) {
        const data = JSON.parse(FS.readFileSync(TOKEN_FILE));
        ACCESS_TOKEN = data.access_token;
        REFRESH_TOKEN = data.refresh_token;
        try {
            await refreshToken();
        } catch (e) {
            console.log('刷新失败，重新授权');
            const newData = await authorize();
            ACCESS_TOKEN = newData.access_token;
            REFRESH_TOKEN = newData.refresh_token;
        }
    } else {
        const data = await authorize();
        ACCESS_TOKEN = data.access_token;
        REFRESH_TOKEN = data.refresh_token;
    }
    setInterval(async () => {
        try {
            await refreshToken();
        } catch (e) {
            console.error('自动刷新失败', e.message);
        }
    }, 50 * 60 * 1000);
}

async function apiRequest(method, path, body = null, extraHeaders = {}) {
    const options = {
        hostname: 'driveapis.cloud.huawei.com.cn',
        path,
        method,
        headers: {
            'Authorization': `Bearer ${ACCESS_TOKEN}`,
            'Accept': 'application/json',
            ...extraHeaders
        }
    };
    let postData = null;
    if (body && typeof body === 'object') {
        postData = JSON.stringify(body);
        options.headers['Content-Type'] = 'application/json';
        options.headers['Content-Length'] = Buffer.byteLength(postData);
    } else if (typeof body === 'string') {
        postData = body;
        options.headers['Content-Length'] = Buffer.byteLength(postData);
    }
    let res = await httpsRequest(options, postData);
    if (res.statusCode === 401) {
        await refreshToken();
        options.headers['Authorization'] = `Bearer ${ACCESS_TOKEN}`;
        res = await httpsRequest(options, postData);
    }
    return res;
}

async function apiJSON(method, path, body = null, extraHeaders = {}) {
    const res = await apiRequest(method, path, body, extraHeaders);
    const parsed = safeJsonParse(res.raw, `${method} ${path}`);
    if (!parsed.success || (parsed.data && parsed.data.error)) {
        throw new Error(parsed.data?.error?.message || `API错误 ${res.statusCode}: ${res.raw}`);
    }
    return parsed.data;
}

async function getRootId() {
    return 'root';
}

async function listFolder(folderId) {
    const query = `queryParam=${encodeURIComponent(`'${folderId}' in parentFolder`)}&fields=*&pageSize=200`;
    let allFiles = [], cursor = '';
    do {
        const resp = await apiJSON('GET', `/drive/v1/files?${query}${cursor ? `&cursor=${cursor}` : ''}`);
        if (resp.files) allFiles.push(...resp.files);
        cursor = resp.nextCursor || '';
    } while (cursor);
    return allFiles.filter(f => !SKIP_FILES.includes(f.fileName));
}

async function getFileInfoById(fileId) {
    return await apiJSON('GET', `/drive/v1/files/${fileId}?fields=*`);
}

const pathCache = new Map();
async function getFileIdByPath(fullPath) {
    if (typeof fullPath !== 'string') fullPath = String(fullPath);
    if (!ROOT_ID) ROOT_ID = await getRootId();

    if (fullPath === '/' || fullPath === '') {
        return { fileId: ROOT_ID, mimeType: 'application/vnd.huawei-apps.folder' };
    }
    const norm = fullPath.endsWith('/') ? fullPath.slice(0, -1) : fullPath;
    const now = Date.now();
    if (pathCache.has(norm) && pathCache.get(norm).expires > now) {
        return pathCache.get(norm);
    }
    const parts = norm.split('/').filter(p => p);
    let currentId = ROOT_ID;
    for (let i = 0; i < parts.length; i++) {
        const name = parts[i];
        const children = await listFolder(currentId);
        const found = children.find(c => c.fileName === name);
        if (!found) return null;
        currentId = found.id;

        const currentPath = '/' + parts.slice(0, i + 1).join('/');
        pathCache.set(currentPath, {
            fileId: found.id,
            mimeType: found.mimeType,
            size: found.size,
            editedTime: found.editedTime,
            expires: now + 30000
        });

        if (i === parts.length - 1) {
            return pathCache.get(norm);
        }
        if (found.mimeType !== 'application/vnd.huawei-apps.folder') return null;
    }
    return null;
}

async function createFolder(parentId, folderName) {
    const body = { fileName: folderName, mimeType: 'application/vnd.huawei-apps.folder', parentFolder: [parentId] };
    return await apiJSON('POST', '/drive/v1/files?fields=*', body);
}

async function deleteFile(fileId) {
    await apiRequest('DELETE', `/drive/v1/files/${fileId}`);
}

async function updateFileMetadata(fileId, newName = null, newParentId = null) {
    const updates = {};
    if (newName) updates.fileName = newName;
    if (newParentId) updates.parentFolder = [newParentId];
    if (Object.keys(updates).length === 0) return;
    await apiJSON('PATCH', `/drive/v1/files/${fileId}?fields=*`, updates);
    pathCache.clear();
}

async function downloadAsStream(fileId) {
    const makeRequest = () => new Promise((resolve, reject) => {
        const req = HTTPS.request({
            hostname: 'driveapis.cloud.huawei.com.cn',
            path: `/drive/v1/files/${fileId}?form=content`,
            headers: { 'Authorization': `Bearer ${ACCESS_TOKEN}` }
        }, resolve);
        req.on('error', reject);
        req.end();
    });
    let resp = await makeRequest();
    if (resp.statusCode === 401) {
        await refreshToken();
        resp = await makeRequest();
    }
    if (resp.statusCode !== 200) {
        let errBody = '';
        resp.on('data', chunk => errBody += chunk);
        await new Promise(resolve => resp.on('end', resolve));
        throw new Error(`下载失败 ${resp.statusCode}: ${errBody}`);
    }
    return resp;
}

async function createUploadSession(parentId, fileName, fileSize, mimeType) {
    const body = { fileName, parentFolder: [parentId] };
    const res = await apiRequest('POST', '/upload/drive/v1/files?uploadType=resume', body, {
        'X-Upload-Content-Type': mimeType,
        'X-Upload-Content-Length': fileSize
    });
    if (res.statusCode >= 400) {
        throw new Error(`创建上传会话失败[${res.statusCode}]: ${res.raw}`);
    }
    return res.headers.location;
}

async function uploadChunk(uploadUrl, start, end, total, chunk, mimeType) {
    const urlObj = new URL(uploadUrl);
    const options = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'PUT',
        headers: {
            'Content-Type': mimeType,
            'Content-Length': chunk.length,
            'Content-Range': `bytes ${start}-${end - 1}/${total}`,
            'Authorization': `Bearer ${ACCESS_TOKEN}`
        }
    };
    const res = await httpsRequest(options, chunk);
    if (res.statusCode === 200 || res.statusCode === 201) return { completed: true };
    if (res.statusCode === 308) {
        const range = res.headers['range'];
        const uploaded = range ? parseInt(range.match(/bytes=0-(\d+)/)[1]) + 1 : 0;
        return { completed: false, uploaded };
    }
    throw new Error(`分片上传失败 ${res.statusCode}`);
}

async function uploadStream(parentId, fileName, fileSize, tempFilePath, mimeType) {
    const uploadUrl = await createUploadSession(parentId, fileName, fileSize, mimeType);

    if (fileSize > 0) {
        let start = 0;
        while (start < fileSize) {
            const end = Math.min(start + MAX_UPLOAD_SIZE, fileSize);
            const chunkStream = FS.createReadStream(tempFilePath, { start, end: end - 1 });
            const chunkBuffer = await new Promise((resolve, reject) => {
                const chunks = [];
                chunkStream.on('data', c => chunks.push(c));
                chunkStream.on('end', () => resolve(Buffer.concat(chunks)));
                chunkStream.on('error', reject);
            });

            const result = await uploadChunk(uploadUrl, start, end, fileSize, chunkBuffer, mimeType);
            if (result.completed) break;
            start = result.uploaded !== undefined ? result.uploaded : end;
        }
    }

    const finalOptions = {
        hostname: new URL(uploadUrl).hostname,
        path: new URL(uploadUrl).pathname + new URL(uploadUrl).search,
        method: 'PUT',
        headers: { 'Content-Length': 0, 'Authorization': `Bearer ${ACCESS_TOKEN}` }
    };
    const finalRes = await httpsRequest(finalOptions);
    if (finalRes.statusCode !== 200 && finalRes.statusCode !== 201) {
        throw new Error(`确认上传完成失败 ${finalRes.statusCode}: ${finalRes.raw}`);
    }
    return safeJsonParse(finalRes.raw)?.data;
}

class HuaweiFileSystem extends webdav.FileSystem {
    constructor() {
        super();
        this.locks = new webdav.LocalLockManager();
        this.props = new webdav.LocalPropertyManager();
    }

    _lockManager(path, ctx, callback) { callback(null, this.locks); }

    _propertyManager(path, ctx, callback) { callback(null, this.props); }

    _readDir(pathObj, ctx, callback) {
        const path = pathObj.toString();
        const norm = path.endsWith('/') && path !== '/' ? path.slice(0, -1) : path;

        (async () => {
            try {
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                if (info.mimeType !== 'application/vnd.huawei-apps.folder')
                    return callback(new Error('Not a directory'));

                const children = await listFolder(info.fileId);
                const now = Date.now();

                const childNames = children.map(c => {
                    const childPath = (norm === '/' ? '' : norm) + '/' + c.fileName;
                    pathCache.set(childPath, {
                        fileId: c.id,
                        mimeType: c.mimeType,
                        size: c.size,
                        editedTime: c.editedTime,
                        expires: now + 60000
                    });
                    return c.fileName;
                });

                callback(null, childNames);
            } catch (err) { callback(err); }
        })();
    }

    _type(pathObj, ctx, callback) {
        const path = pathObj.toString();
        (async () => {
            try {
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                const type = info.mimeType === 'application/vnd.huawei-apps.folder'
                    ? webdav.ResourceType.Directory
                    : webdav.ResourceType.File;
                callback(null, type);
            } catch (err) { callback(err); }
        })();
    }

    _size(pathObj, ctx, callback) {
        const path = pathObj.toString();
        (async () => {
            try {
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                if (info.mimeType === 'application/vnd.huawei-apps.folder') return callback(null, 0);
                if (info.size !== undefined) return callback(null, info.size || 0);

                const fileInfo = await getFileInfoById(info.fileId);
                callback(null, fileInfo.size || 0);
            } catch (err) { callback(err); }
        })();
    }

    _lastModifiedDate(pathObj, ctx, callback) {
        const path = pathObj.toString();
        (async () => {
            try {
                if (path === '/') return callback(null, Date.now());
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                if (info.editedTime) return callback(null, new Date(info.editedTime).getTime());

                const fileInfo = await getFileInfoById(info.fileId);
                callback(null, new Date(fileInfo.editedTime).getTime());
            } catch (err) { callback(err); }
        })();
    }

    _creationDate(pathObj, ctx, callback) { this._lastModifiedDate(pathObj, ctx, callback); }

    _openReadStream(pathObj, ctx, callback) {
        const path = pathObj.toString();
        console.log(`[WebDAV] 下载文件: ${path}`);
        (async () => {
            try {
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                if (info.mimeType === 'application/vnd.huawei-apps.folder')
                    return callback(new Error('Cannot read folder'));
                const stream = await downloadAsStream(info.fileId);
                callback(null, stream);
            } catch (err) { callback(err); }
        })();
    }

    _create(pathObj, ctx, callback) {
        const path = pathObj.toString();
        const norm = path.endsWith('/') && path !== '/' ? path.slice(0, -1) : path;
        const type = ctx.type;

        (async () => {
            try {
                if (type === webdav.ResourceType.File) {
                    pathCache.set(norm, {
                        fileId: 'virtual_' + Date.now(),
                        mimeType: 'application/octet-stream',
                        size: 0,
                        editedTime: new Date().toISOString(),
                        expires: Date.now() + 60000
                    });
                    return callback(null);
                }

                console.log(`[WebDAV] 创建目录: ${path}`);
                const parentPath = PATH.posix.dirname(path);
                const folderName = PATH.posix.basename(path);
                const parentInfo = await getFileIdByPath(parentPath);

                if (!parentInfo || String(parentInfo.fileId).startsWith('virtual_')) {
                    return callback(ERR_NOT_FOUND);
                }

                await createFolder(parentInfo.fileId, folderName);
                pathCache.clear();
                callback(null);
            } catch (err) { callback(err); }
        })();
    }

    _openWriteStream(pathObj, ctx, callback) {
        const path = pathObj.toString();
        const parentPath = PATH.posix.dirname(path);
        const fileName = PATH.posix.basename(path);

        console.log(`[WebDAV] 准备写入: ${path}`);
        const tempFilePath = PATH.join(OS.tmpdir(), `upload_${Date.now()}_${Math.random().toString(36).substring(2)}`);
        const fileStream = FS.createWriteStream(tempFilePath);

        const writable = new Writable({
            write(chunk, enc, cb) {
                fileStream.write(chunk, enc, cb);
            },
            final(cb) {
                fileStream.end(async () => {
                    try {
                        const fileSize = FS.statSync(tempFilePath).size;
                        const parentInfo = await getFileIdByPath(parentPath);
                        if (!parentInfo || String(parentInfo.fileId).startsWith('virtual_')) {
                            throw ERR_NOT_FOUND;
                        }

                        const existingInfo = await getFileIdByPath(path);
                        if (existingInfo && !String(existingInfo.fileId).startsWith('virtual_')) {
                            console.log(`[WebDAV] 网盘已存在同名文件，正在覆盖...`);
                            await deleteFile(existingInfo.fileId);
                        }

                        const mime = ctx.headers?.['content-type'] || getMimeType(fileName);

                        console.log(`[WebDAV] 开始上传 (${(fileSize / 1024 / 1024).toFixed(2)} MB)...`);
                        await uploadStream(parentInfo.fileId, fileName, fileSize, tempFilePath, mime);

                        pathCache.clear();
                        try { FS.unlinkSync(tempFilePath); } catch (e) { }
                        console.log(`[WebDAV] 上传成功: ${path}`);
                        cb();
                    } catch (err) {
                        console.error(`[WebDAV] 写入失败:`, err.message);
                        try { FS.unlinkSync(tempFilePath); } catch (e) { }
                        cb(err);
                    }
                });
            }
        });
        callback(null, writable);
    }

    _delete(pathObj, ctx, callback) {
        const path = pathObj.toString();
        console.log(`[WebDAV] 删除: ${path}`);
        (async () => {
            try {
                if (path === '/') return callback(new Error('Cannot delete root'));
                const info = await getFileIdByPath(path);
                if (!info) return callback(ERR_NOT_FOUND);
                await deleteFile(info.fileId);
                pathCache.clear();
                callback(null);
            } catch (err) { callback(err); }
        })();
    }

    _move(fromObj, toObj, ctx, callback) {
        const from = fromObj.toString(), to = toObj.toString();
        console.log(`[WebDAV] 移动/重命名: ${from} -> ${to}`);
        (async () => {
            try {
                if (from === '/') return callback(new Error('Cannot move root'));
                const srcInfo = await getFileIdByPath(from);
                if (!srcInfo) return callback(ERR_NOT_FOUND);
                const destParentPath = PATH.posix.dirname(to);
                const destName = PATH.posix.basename(to);
                let destParentId = ROOT_ID;
                if (destParentPath !== '/' && destParentPath !== '.') {
                    const destParentInfo = await getFileIdByPath(destParentPath);
                    if (!destParentInfo) return callback(ERR_NOT_FOUND);
                    destParentId = destParentInfo.fileId;
                }
                let newName = null, newParentId = null;
                if (destName !== PATH.posix.basename(from)) newName = destName;
                let currentParentId = ROOT_ID;
                try {
                    const fileInfo = await getFileInfoById(srcInfo.fileId);
                    currentParentId = fileInfo.parentFolder?.[0] || ROOT_ID;
                } catch (e) { }
                if (destParentId !== currentParentId) newParentId = destParentId;
                await updateFileMetadata(srcInfo.fileId, newName, newParentId);
                callback(null);
            } catch (err) { callback(err); }
        })();
    }
}

async function main() {
    await initToken();
    ROOT_ID = await getRootId();
    console.log(`华为云盘 WebDAV 服务启动中...`);

    const userManager = new webdav.SimpleUserManager();
    const privilegeManager = new webdav.SimplePathPrivilegeManager();
    const user = userManager.addUser(WEBDAV_USER, WEBDAV_PASSWORD, false);
    privilegeManager.setRights(user, '/', ['all']);

    const server = new webdav.WebDAVServer({
        httpAuthentication: new webdav.HTTPBasicAuthentication(userManager, 'Huawei Cloud'),
        privilegeManager
    });

    server.setFileSystem('/', new HuaweiFileSystem());

    server.beforeRequest((ctx, next) => {
        if (ctx.request.method !== 'PROPFIND') {
            console.log(`[HTTP] ${ctx.request.method} ${ctx.request.url}`);
        }
        next();
    });

    process.on('uncaughtException', err => console.error('未捕获异常:', err));
    process.on('unhandledRejection', reason => console.error('未处理拒绝:', reason));

    server.start(WEBDAV_PORT, () => {
        console.log(`==========================================`);
        console.log(`✅ 服务正在运行`);
        console.log(`🌐 地址: http://127.0.0.1:${WEBDAV_PORT}`);
        console.log(`👤 账号: ${WEBDAV_USER}`);
        console.log(`🔑 密码: ${WEBDAV_PASSWORD}`);
        console.log(`==========================================`);
    });
}

main().catch(console.error);