const FS = require('fs');
const PATH = require('path');
const HTTPS = require('https');
const HTTP = require('http');
const QS = require('querystring');
const READLINE = require('readline');
const OS = require('os');
const { Writable } = require('stream');
const webdav = require('webdav-server').v2;
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');

const CLIENT_ID = '117755925';
const CLIENT_SECRET = 'ba95fc3b100404e22043431a7fca19ea916fe38597f121bfa7908f02ffe1199a';
const REDIRECT_URI = 'https://webdav.rzdpai.com';
const SCOPE = 'openid+profile+https://www.huawei.com/auth/drive+https://www.huawei.com/auth/drive.file';
const AUTHORIZE_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/authorize?response_type=code&access_type=offline&state=webdav_huawei&client_id=' + CLIENT_ID + '&redirect_uri=' + REDIRECT_URI + '&scope=' + SCOPE;
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024;
const SKIP_FILES = ['.DS_Store'];

const CONFIG_FILE = PATH.join(__dirname, 'users.json');
const LOG_FILE = PATH.join(__dirname, 'webdav.log');
const WEBDAV_PORT = process.env.PORT || 1900;
const ADMIN_PORT = process.env.ADMIN_PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ERR_NOT_FOUND = webdav.Errors.ResourceNotFound;
const ERR_BAD_AUTH = webdav.Errors.BadAuthentication;
const DEBUG = process.env.DEBUG === '1';

const keepAliveAgent = new HTTPS.Agent({
    keepAlive: true,
    keepAliveMsecs: 15000,
    maxSockets: 100,
    maxFreeSockets: 10
});

let usersConfig = [];
if (FS.existsSync(CONFIG_FILE)) usersConfig = JSON.parse(FS.readFileSync(CONFIG_FILE, 'utf8'));

let isRunning = false;
let serverInstance = null;
let httpServer = null;
const pathCaches = {};
const refreshingTokens = {};

function log(msg) { FS.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`); }
function debug(msg) { if (DEBUG) log(msg); }
function saveConfig() { FS.writeFileSync(CONFIG_FILE, JSON.stringify(usersConfig, null, 2), 'utf8'); }
function safeJsonParse(data) { try { return { success: true, data: JSON.parse(data) }; } catch (e) { return { success: false, error: e }; } }

function httpsRequest(options, postData = null) {
    if (!options.agent) {
        options.agent = keepAliveAgent;
    }
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

async function getHuaweiUserInfo(accessToken) {
    const res = await httpsRequest({
        hostname: 'driveapis.cloud.huawei.com.cn',
        path: '/drive/v1/about?fields=*',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' }
    });
    return JSON.parse(res.raw);
}

async function authorizeNewUser(rl) {
    console.log(AUTHORIZE_URL);
    const code = (await new Promise(r => rl.question('Token: ', r))).trim();
    const postData = QS.stringify({ grant_type: 'authorization_code', code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uri: REDIRECT_URI });
    const { raw } = await httpsRequest({
        hostname: 'oauth-login.cloud.huawei.com', port: 443, path: '/oauth2/v3/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData, 'utf8') }
    }, postData);
    const result = safeJsonParse(raw);
    if (!result.success || result.data.error) throw new Error('Auth failed');
    return result.data;
}

function normalizeUsername(v) { return String(v ?? '').trim().toLowerCase(); }
function userKey(username) { return normalizeUsername(username); }
function findConfigUser(username) {
    const n = normalizeUsername(username);
    return usersConfig.find(u => normalizeUsername(u.username) === n) || null;
}

function usernameFromUserObject(user) {
    if (!user) return null;
    if (typeof user === 'string') return normalizeUsername(user);
    const fields = ['username', 'userName', 'login', 'name', 'uid', 'id', '_username', '_name', 'displayName', 'account', 'user'];
    for (const f of fields) {
        const v = user[f];
        if (v && typeof v === 'string') return normalizeUsername(v);
    }
    return null;
}

function getHeaderCaseInsensitive(headers, name) {
    if (!headers) return null;
    const lower = name.toLowerCase();
    for (const key of Object.keys(headers)) if (key.toLowerCase() === lower) return headers[key];
    return null;
}

function usernameFromBasicAuthHeader(authHeader) {
    if (!authHeader || typeof authHeader !== 'string') return null;
    const m = authHeader.match(/^Basic\s+(.+)$/i);
    if (!m) return null;
    try {
        const decoded = Buffer.from(m[1], 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx < 0) return null;
        return normalizeUsername(decoded.slice(0, idx));
    } catch (e) { return null; }
}

function extractUsernameFromCtx(ctx) {
    const userCandidates = [ctx?.user, ctx?.context?.user, ctx?.rootContext?.user, ctx?.requestContext?.user, ctx?.context?.request?.user, ctx?.rootContext?.request?.user];
    for (const u of userCandidates) { const name = usernameFromUserObject(u); if (name) return name; }
    const headerCandidates = [ctx?.headers, ctx?.request?.headers, ctx?.context?.headers, ctx?.context?.request?.headers, ctx?.rootContext?.request?.headers];
    for (const h of headerCandidates) { const auth = getHeaderCaseInsensitive(h, 'authorization'); const name = usernameFromBasicAuthHeader(auth); if (name) return name; }
    debug(`Cannot extract username. ctx keys: ${Object.keys(ctx || {}).join(', ')}`);
    return null;
}

function resolveUser(ctx) {
    const username = extractUsernameFromCtx(ctx);
    if (!username) return null;
    if (username.startsWith('_') || username === 'anonymous' || username === 'default') return null;
    const configUser = findConfigUser(username);
    if (!configUser) { debug(`User "${username}" not found in config`); return null; }
    const normalized = normalizeUsername(configUser.username);
    debug(`Resolved user: ${normalized}`);
    return normalized;
}

function requireUser(ctx, callback) {
    const user = resolveUser(ctx);
    if (!user) callback(ERR_BAD_AUTH);
    return user;
}

function withUser(ctx, callback, handler) {
    const username = requireUser(ctx, callback);
    if (!username) return;
    Promise.resolve(handler(username)).then(result => callback(null, result)).catch(err => callback(err));
}

async function refreshToken(username) {
    const u = findConfigUser(username);
    if (!u) throw new Error('No user');
    const key = userKey(username);
    if (refreshingTokens[key]) return refreshingTokens[key];
    refreshingTokens[key] = (async () => {
        try {
            const postData = QS.stringify({ grant_type: 'refresh_token', refresh_token: u.token.refresh_token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
            const { raw } = await httpsRequest({
                hostname: 'oauth-login.cloud.huawei.com', port: 443, path: '/oauth2/v3/token', method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData, 'utf8') }
            }, postData);
            const result = safeJsonParse(raw);
            if (!result.success || result.data.error) throw new Error('Refresh failed');
            if (!result.data.refresh_token) result.data.refresh_token = u.token.refresh_token;
            u.token = result.data;
            saveConfig();
        } finally { delete refreshingTokens[key]; }
    })();
    return refreshingTokens[key];
}

function getUserToken(username) {
    const u = findConfigUser(username);
    if (!u || !u.token || !u.token.access_token) return null;
    return u.token;
}

async function requestWithTokenRetry(username, requestFn) {
    let token = getUserToken(username);
    if (!token) throw new Error('No token');
    let res = await requestFn(token);
    if (res.statusCode === 401) {
        await refreshToken(username);
        token = getUserToken(username);
        if (!token) throw new Error('Token refresh failed');
        res = await requestFn(token);
    }
    return res;
}

async function apiRequest(username, method, path, body = null, extra = {}) {
    const make = async (token) => {
        const opt = {
            hostname: 'driveapis.cloud.huawei.com.cn', path, method,
            headers: { 'Authorization': `Bearer ${token.access_token}`, 'Accept': 'application/json', ...extra }
        };
        let post = null;
        if (body && typeof body === 'object') { post = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; opt.headers['Content-Length'] = Buffer.byteLength(post); }
        else if (typeof body === 'string') { post = body; opt.headers['Content-Length'] = Buffer.byteLength(post); }
        return await httpsRequest(opt, post);
    };
    return await requestWithTokenRetry(username, make);
}

async function apiJSON(username, method, path, body = null, extra = {}) {
    const res = await apiRequest(username, method, path, body, extra);
    const parsed = safeJsonParse(res.raw);
    if (!parsed.success || (parsed.data && parsed.data.error)) throw new Error(parsed.data?.error?.message || `API error ${res.statusCode}`);
    return parsed.data;
}

function getMimeType(fileName) {
    const ext = PATH.extname(fileName).toLowerCase();
    const types = { '.apk':'application/vnd.android.package-archive','.mp4':'video/mp4','.mkv':'video/x-matroska','.avi':'video/x-msvideo','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.gif':'image/gif','.txt':'text/plain','.js':'application/x-javascript','.json':'application/json','.pdf':'application/pdf','.zip':'application/zip','.rar':'application/x-rar-compressed' };
    return types[ext] || 'application/octet-stream';
}

async function listFolder(username, folderId) {
    const query = `queryParam=${encodeURIComponent(`'${folderId}' in parentFolder`)}&fields=*&pageSize=200`;
    let all = [], cursor = '';
    do {
        const resp = await apiJSON(username, 'GET', `/drive/v1/files?${query}${cursor ? `&cursor=${cursor}` : ''}`);
        if (resp.files) all.push(...resp.files);
        cursor = resp.nextCursor || '';
    } while (cursor);
    return all.filter(f => !SKIP_FILES.includes(f.fileName));
}

async function getFileInfoById(username, fileId) { return await apiJSON(username, 'GET', `/drive/v1/files/${fileId}?fields=*`); }

async function getFileIdByPath(username, fullPath) {
    if (fullPath === '/' || fullPath === '') return { fileId: 'root', mimeType: 'application/vnd.huawei-apps.folder' };
    const norm = fullPath.endsWith('/') ? fullPath.slice(0, -1) : fullPath;
    const now = Date.now();
    const key = userKey(username);
    if (!pathCaches[key]) pathCaches[key] = new Map();
    const cache = pathCaches[key];
    if (cache.has(norm) && cache.get(norm).expires > now) return cache.get(norm);
    const parts = norm.split('/').filter(p => p);
    let currentId = 'root';
    for (let i = 0; i < parts.length; i++) {
        const name = parts[i];
        const children = await listFolder(username, currentId);
        const found = children.find(c => c.fileName === name);
        if (!found) return null;
        currentId = found.id;
        const currentPath = '/' + parts.slice(0, i + 1).join('/');
        cache.set(currentPath, { fileId: found.id, mimeType: found.mimeType, size: found.size, editedTime: found.editedTime, expires: now + 30000 });
        if (i === parts.length - 1) return cache.get(norm);
        if (found.mimeType !== 'application/vnd.huawei-apps.folder') return null;
    }
    return null;
}

async function createFolder(username, parentId, folderName) {
    return await apiJSON(username, 'POST', '/drive/v1/files?fields=*', { fileName: folderName, mimeType: 'application/vnd.huawei-apps.folder', parentFolder: [parentId] });
}

async function deleteFile(username, fileId) { await apiRequest(username, 'DELETE', `/drive/v1/files/${fileId}`); }
async function updateFileMetadata(username, fileId, newName = null, newParentId = null) {
    const updates = {};
    if (newName) updates.fileName = newName;
    if (newParentId) updates.parentFolder = [newParentId];
    if (Object.keys(updates).length === 0) return;
    await apiJSON(username, 'PATCH', `/drive/v1/files/${fileId}?fields=*`, updates);
}

async function downloadAsStream(username, fileId, rangeHeader = null) {
    const make = async (token) => new Promise((resolve, reject) => {
        const headers = { 'Authorization': `Bearer ${token.access_token}` };
        if (rangeHeader) headers['Range'] = rangeHeader;
        const req = HTTPS.request({
            hostname: 'driveapis.cloud.huawei.com.cn',
            path: `/drive/v1/files/${fileId}?form=content`,
            headers: headers,
            agent: keepAliveAgent
        }, resolve);
        req.on('error', reject);
        req.end();
    });
    const resp = await requestWithTokenRetry(username, make);
    if (resp.statusCode !== 200 && resp.statusCode !== 206) {
        let err = '';
        resp.on('data', c => err += c);
        await new Promise(r => resp.on('end', r));
        throw new Error(`Download failed ${resp.statusCode}: ${err}`);
    }
    return resp;
}

async function createUploadSession(username, parentId, fileName, fileSize, mimeType) {
    const res = await apiRequest(username, 'POST', '/upload/drive/v1/files?uploadType=resume', { fileName, parentFolder: [parentId] }, { 'X-Upload-Content-Type': mimeType, 'X-Upload-Content-Length': fileSize });
    if (res.statusCode >= 400) throw new Error(`Upload session failed: ${res.raw}`);
    return res.headers.location;
}

async function uploadChunk(username, uploadUrl, start, end, total, chunk, mimeType) {
    const urlObj = new URL(uploadUrl);
    const make = async (token) => {
        return await httpsRequest({
            hostname: urlObj.hostname, path: urlObj.pathname + urlObj.search, method: 'PUT',
            headers: { 'Content-Type': mimeType, 'Content-Length': chunk.length, 'Content-Range': `bytes ${start}-${end - 1}/${total}`, 'Authorization': `Bearer ${token.access_token}` }
        }, chunk);
    };
    const res = await requestWithTokenRetry(username, make);
    if (res.statusCode === 200 || res.statusCode === 201) return { completed: true };
    if (res.statusCode === 308) {
        const range = res.headers['range'];
        const uploaded = range ? parseInt(range.match(/bytes=0-(\d+)/)[1]) + 1 : 0;
        return { completed: false, uploaded };
    }
    throw new Error(`Chunk upload failed ${res.statusCode}`);
}

async function uploadStream(username, parentId, fileName, fileSize, tempFilePath, mimeType) {
    const uploadUrl = await createUploadSession(username, parentId, fileName, fileSize, mimeType);
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
            const result = await uploadChunk(username, uploadUrl, start, end, fileSize, chunkBuffer, mimeType);
            if (result.completed) break;
            start = result.uploaded !== undefined ? result.uploaded : end;
        }
    }
}

class HuaweiFileSystem extends webdav.FileSystem {
    constructor() { super(); this.locks = new webdav.LocalLockManager(); this.props = new webdav.LocalPropertyManager(); }

    _normalize(pObj) {
        let p = pObj.toString();
        try {
            p = decodeURIComponent(p);
        } catch (e) {}
        p = p.replace(/^(?:\/https?:\/[^\/]+)+/i, '');
        return p === '' ? '/' : p;
    }

    _lockManager(p, ctx, cb) { cb(null, this.locks); }
    _propertyManager(p, ctx, cb) { cb(null, this.props); }

    _type(pObj, ctx, cb) {
        const p = this._normalize(pObj);
        withUser(ctx, cb, async u => { if (p === '/') return webdav.ResourceType.Directory; const info = await getFileIdByPath(u, p); if (!info) throw ERR_NOT_FOUND; return info.mimeType === 'application/vnd.huawei-apps.folder' ? webdav.ResourceType.Directory : webdav.ResourceType.File; });
    }

    _readDir(pObj, ctx, cb) {
        const p = this._normalize(pObj), norm = p === '/' ? '/' : p.replace(/\/$/, '');
        withUser(ctx, cb, async u => { const info = await getFileIdByPath(u, p); if (!info) throw ERR_NOT_FOUND; if (info.mimeType !== 'application/vnd.huawei-apps.folder') throw new Error('Not a directory'); const children = await listFolder(u, info.fileId); const now = Date.now(); const key = userKey(u); if (!pathCaches[key]) pathCaches[key] = new Map(); children.forEach(c => { const childPath = (norm === '/' ? '' : norm) + '/' + c.fileName; pathCaches[key].set(childPath, { fileId: c.id, mimeType: c.mimeType, size: c.size, editedTime: c.editedTime, expires: now + 60000 }); }); return children.map(c => c.fileName); });
    }

    _size(pObj, ctx, cb) {
        const p = this._normalize(pObj);
        withUser(ctx, cb, async u => { if (p === '/') return 0; const info = await getFileIdByPath(u, p); if (!info) throw ERR_NOT_FOUND; if (info.mimeType === 'application/vnd.huawei-apps.folder') return 0; if (info.size !== undefined) return info.size || 0; const fi = await getFileInfoById(u, info.fileId); return fi.size || 0; });
    }

    _lastModifiedDate(pObj, ctx, cb) {
        const p = this._normalize(pObj);
        withUser(ctx, cb, async u => { if (p === '/') return Date.now(); const info = await getFileIdByPath(u, p); if (!info) throw ERR_NOT_FOUND; if (info.editedTime) return new Date(info.editedTime).getTime(); const fi = await getFileInfoById(u, info.fileId); return new Date(fi.editedTime).getTime(); });
    }

    _creationDate(pObj, ctx, cb) { this._lastModifiedDate(pObj, ctx, cb); }

    _openReadStream(pObj, ctx, cb) {
        const p = this._normalize(pObj);
        withUser(ctx, cb, async u => {
            if (p === '/') throw new Error('Cannot read root');
            const info = await getFileIdByPath(u, p);
            if (!info) throw ERR_NOT_FOUND;
            if (info.mimeType === 'application/vnd.huawei-apps.folder') throw new Error('Cannot read folder');
            return await downloadAsStream(u, info.fileId, null);
        });
    }

    _create(pObj, ctx, cb) {
        const p = this._normalize(pObj), norm = p === '/' ? '/' : p.replace(/\/$/, '');
        const type = ctx.type;
        withUser(ctx, cb, async u => { if (type === webdav.ResourceType.File) { const key = userKey(u); if (!pathCaches[key]) pathCaches[key] = new Map(); pathCaches[key].set(norm, { fileId: 'virtual_' + Date.now(), mimeType: 'application/octet-stream', size: 0, editedTime: new Date().toISOString(), expires: Date.now() + 60000 }); return; } const parent = PATH.posix.dirname(p), folder = PATH.posix.basename(p); const parentInfo = await getFileIdByPath(u, parent); if (!parentInfo || String(parentInfo.fileId).startsWith('virtual_')) throw ERR_NOT_FOUND; await createFolder(u, parentInfo.fileId, folder); const key = userKey(u); if (pathCaches[key]) pathCaches[key].clear(); });
    }

    _openWriteStream(pObj, ctx, cb) {
        const p = this._normalize(pObj), parent = PATH.posix.dirname(p), fileName = PATH.posix.basename(p);
        const temp = PATH.join(OS.tmpdir(), `upload_${Date.now()}_${Math.random().toString(36).substring(2)}`);
        const fileStream = FS.createWriteStream(temp);
        const writable = new Writable({
            write(chunk, enc, cb2) { fileStream.write(chunk, enc, cb2); },
            final(cb2) {
                fileStream.end(async () => {
                    try {
                        const u = resolveUser(ctx);
                        if (!u) throw ERR_BAD_AUTH;
                        const size = FS.statSync(temp).size;
                        const parentInfo = await getFileIdByPath(u, parent);
                        if (!parentInfo || String(parentInfo.fileId).startsWith('virtual_')) throw ERR_NOT_FOUND;
                        const existing = await getFileIdByPath(u, p);
                        if (existing && !String(existing.fileId).startsWith('virtual_')) await deleteFile(u, existing.fileId);
                        const mime = ctx.headers?.['content-type'] || getMimeType(fileName);
                        await uploadStream(u, parentInfo.fileId, fileName, size, temp, mime);
                        const key = userKey(u);
                        if (pathCaches[key]) pathCaches[key].clear();
                        cb2();
                    } catch (err) { cb2(err); }
                    finally { try { FS.unlinkSync(temp); } catch (e) {} }
                });
            }
        });
        cb(null, writable);
    }

    _delete(pObj, ctx, cb) {
        const p = this._normalize(pObj);
        withUser(ctx, cb, async u => { if (p === '/') throw new Error('Cannot delete root'); const info = await getFileIdByPath(u, p); if (!info) throw ERR_NOT_FOUND; await deleteFile(u, info.fileId); const key = userKey(u); if (pathCaches[key]) pathCaches[key].clear(); });
    }

    _move(fromObj, toObj, ctx, cb) {
        const from = this._normalize(fromObj), to = this._normalize(toObj);
        withUser(ctx, cb, async u => { if (from === '/') throw new Error('Cannot move root'); const src = await getFileIdByPath(u, from); if (!src) throw ERR_NOT_FOUND; const destParent = PATH.posix.dirname(to), destName = PATH.posix.basename(to); let destParentId = 'root'; if (destParent !== '/' && destParent !== '.') { const dp = await getFileIdByPath(u, destParent); if (!dp) throw ERR_NOT_FOUND; destParentId = dp.fileId; } let newName = null, newParentId = null; if (destName !== PATH.posix.basename(from)) newName = destName; let curParent = 'root'; try { const fi = await getFileInfoById(u, src.fileId); curParent = fi.parentFolder?.[0] || 'root'; } catch (e) {} if (destParentId !== curParent) newParentId = destParentId; await updateFileMetadata(u, src.fileId, newName, newParentId); const key = userKey(u); if (pathCaches[key]) pathCaches[key].clear(); });
    }
}

class AllowAllAuthenticatedPrivilegeManager extends webdav.PrivilegeManager {
    canAccess(ctx, priv, cb) {
        const username = resolveUser(ctx);
        if (!username) {
            cb(ERR_BAD_AUTH);
        } else {
            cb(null, true);
        }
    }
    setRights(user, path, privs) {}
}

async function startServer() {
    if (isRunning) return;
    if (usersConfig.length === 0) { console.log('No users configured.'); return; }
    for (let u of usersConfig) try { await refreshToken(u.username); } catch (e) { log(`Token init failed for ${u.username}: ${e.message}`); }
    const userManager = new webdav.SimpleUserManager();
    for (let u of usersConfig) { userManager.addUser(u.username, u.password, false); pathCaches[userKey(u.username)] = new Map(); }
    serverInstance = new webdav.WebDAVServer({
        httpAuthentication: new webdav.HTTPBasicAuthentication(userManager, 'Huawei Cloud WebDAV'),
        privilegeManager: new AllowAllAuthenticatedPrivilegeManager()
    });
    serverInstance.setFileSystem('/', new HuaweiFileSystem());

    serverInstance.beforeRequest((ctx, next) => {
        debug(`REQ ${ctx.request.method} ${ctx.request.url} user=${extractUsernameFromCtx(ctx) || 'none'}`);
        next();
    });

    serverInstance.afterRequest((ctx, next) => { log(`RES ${ctx.request.method} ${ctx.request.url} -> ${ctx.response.statusCode}`); next(); });

    httpServer = HTTP.createServer(async (req, res) => {
        let cleanPath = req.url;
        try {
            cleanPath = decodeURIComponent(req.url);
        } catch (e) {}
        cleanPath = cleanPath.replace(/^(?:\/https?:\/[^\/]+)+/i, '');
        if (cleanPath === '' || !cleanPath.startsWith('/')) {
            cleanPath = '/' + cleanPath;
        }
        req.url = encodeURI(cleanPath);

        if (req.method === 'GET') {
            try {
                const authHeader = getHeaderCaseInsensitive(req.headers, 'authorization');
                const username = usernameFromBasicAuthHeader(authHeader);
                const configUser = username ? findConfigUser(username) : null;

                if (configUser) {
                    const info = await getFileIdByPath(configUser.username, cleanPath);
                    if (info && info.mimeType !== 'application/vnd.huawei-apps.folder') {
                        const range = getHeaderCaseInsensitive(req.headers, 'range');
                        const resp = await downloadAsStream(configUser.username, info.fileId, range);

                        res.statusCode = resp.statusCode;
                        for (const key in resp.headers) {
                            const lowerKey = key.toLowerCase();
                            if (['content-type', 'content-length', 'content-range', 'accept-ranges', 'content-disposition'].includes(lowerKey)) {
                                res.setHeader(key, resp.headers[key]);
                            }
                        }
                        res.setHeader('Accept-Ranges', 'bytes');
                        resp.pipe(res);

                        req.on('close', () => {
                            resp.destroy();
                        });

                        log(`DIRECT GET ${req.url} -> ${res.statusCode}`);
                        return;
                    }
                }
            } catch (e) {
                debug(`GET intercept error: ${e.message}`);
                if (!res.headersSent) {
                    res.statusCode = 500;
                    res.end('Internal Server Error');
                }
                return;
            }
        }

        serverInstance.executeRequest(req, res);
    });

    await new Promise(r => httpServer.listen(WEBDAV_PORT, r));
    isRunning = true;
    console.log(`WebDAV Server started`);
}

async function stopServer() {
    if (!isRunning) return;
    if (httpServer) {
        await new Promise(r => httpServer.close(r));
        httpServer = null;
    }
    isRunning = false;
    serverInstance = null;
    console.log('WebDAV Server stopped');
}

async function updateAllHuaweiInfo() { for (let u of usersConfig) { try { const info = await getHuaweiUserInfo(u.token.access_token); if (!info.error) u.huawei = info; } catch (e) {} } saveConfig(); }

const adminApp = express();
adminApp.use(bodyParser.urlencoded({ extended: true }));
adminApp.use(bodyParser.json());
adminApp.use(session({ secret: 'webdav-admin-secret', resave: false, saveUninitialized: false, cookie: { maxAge: 3600000 } }));

function requireLogin(req, res, next) {
    if (req.session.loggedIn) return next();
    if (req.path === '/login') return next();
    res.redirect('/login');
}

adminApp.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录</title><style>body{font-family:sans-serif;padding:1rem;max-width:400px;margin:0 auto;background:#f5f5f5}div{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer}h2{margin-top:0}</style></head><body><div><h2>管理后台登录</h2><form method="post" action="/login"><input type="password" name="password" placeholder="密码" required /><button type="submit">登录</button></form></div></body></html>`);
});
adminApp.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/');
    } else {
        res.send('<script>alert("密码错误");location.href="/login";</script>');
    }
});
adminApp.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

adminApp.get('/', requireLogin, (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=yes"><title>华为云盘 WebDAV 管理</title><style>*{box-sizing:border-box}body{font-family:sans-serif;padding:1rem;margin:0;background:#f5f5f5;color:#333}.container{max-width:800px;margin:0 auto}h1{font-size:1.5rem;margin:0 0 0.5rem 0}.info-card{background:white;padding:1rem;border-radius:8px;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,0.1)}.service-status{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-top:0.5rem}.status-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.85rem;font-weight:bold}.status-running{background:#d4edda;color:#155724}.status-stopped{background:#f8d7da;color:#721c24}.service-btn{padding:6px 12px;border:none;border-radius:4px;cursor:pointer;font-size:0.85rem}.service-start{background:#28a745;color:white}.service-stop{background:#dc3545;color:white}table{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1)}th,td{padding:12px 8px;text-align:left;border-bottom:1px solid #ddd}th{background:#f2f2f2;font-weight:600}.actions button{margin-right:8px;padding:6px 12px;border:none;border-radius:4px;cursor:pointer;font-size:0.8rem}.delete-btn{background:#dc3545;color:white}.refresh-btn{background:#28a745;color:white}.add-card{background:white;padding:1rem;border-radius:8px;margin-top:1rem;box-shadow:0 1px 3px rgba(0,0,0,0.1)}.add-card h3{margin-top:0;font-size:1.2rem}.form-group{margin-bottom:1rem}label{display:block;font-weight:600;margin-bottom:0.3rem}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;font-size:1rem}.help-text{font-size:0.8rem;color:#666;margin-top:0.2rem}.btn-primary{background:#007bff;color:white;padding:10px 16px;border:none;border-radius:4px;cursor:pointer;width:100%;font-size:1rem}.btn-secondary{background:#28a745;color:white;padding:10px 16px;border:none;border-radius:4px;cursor:pointer;width:100%;font-size:1rem;margin-bottom:0.5rem}.status{padding:10px;margin-top:0.5rem;border-radius:4px;display:none}.status.error{background:#f8d7da;color:#721c24;display:block}.status.success{background:#d4edda;color:#155724;display:block}.logout-btn{background:#6c757d;color:white;padding:6px 12px;border:none;border-radius:4px;cursor:pointer;font-size:0.85rem;text-decoration:none;display:inline-block}.logout-btn:hover{background:#5a6268}@media (max-width:600px){th,td{font-size:0.8rem;padding:8px 4px}.actions button{padding:4px 8px;font-size:0.7rem}}</style></head><body><div class="container"><div class="info-card"><h1>华为云盘 WebDAV</h1><div class="service-status"><span>WebDAV服务状态：</span><span id="serviceStatus" class="status-badge">加载中...</span><button id="startServiceBtn" class="service-btn service-start">启动服务</button><button id="stopServiceBtn" class="service-btn service-stop">停止服务</button><button id="logoutBtn" class="logout-btn">退出登录</button></div></div><h2>用户列表</h2><table id="userTable"><thead><tr><th>用户名</th><th>华为账号</th><th>存储用量</th><th>操作</th></tr></thead><tbody><tr><td colspan="4">加载中...</tr></tbody></table><div class="add-card"><h3>添加用户</h3><div class="form-group"><label>WebDAV 用户名</label><input type="text" id="webdavUsername" placeholder="例如: mycloud" autocomplete="off"></div><div class="form-group"><label>WebDAV 密码</label><input type="password" id="webdavPassword" placeholder="用于 WebDAV 登录"></div><div class="form-group"><label>华为授权码 (code)</label><input type="text" id="authCode" placeholder="从授权页面复制 code"><div class="help-text">点击下方按钮获取授权码，授权成功后复制地址栏中的 code= 后面的参数</div></div><button id="getCodeBtn" class="btn-secondary">获取授权码</button><button id="addBtn" class="btn-primary">添加用户</button><div id="addStatus" class="status"></div></div></div><script>function showStatus(msg,isError){const div=document.getElementById('addStatus');div.textContent=msg;div.className='status '+(isError?'error':'success');setTimeout(()=>{div.style.display='none';div.className='status';},8000);div.style.display='block';}async function loadUsers(){try{const resp=await fetch('/api/users');if(!resp.ok)throw new Error();const users=await resp.json();const tbody=document.querySelector('#userTable tbody');tbody.innerHTML='';if(users.length===0){tbody.innerHTML='<tr><td colspan="4">暂无用户</td></tr>';return;}for(const u of users){const row=tbody.insertRow();row.insertCell(0).textContent=u.username;row.insertCell(1).textContent=u.huawei?.user?.displayName||u.huawei?.user?.account||'未知';const quota=u.huawei?.storageQuota||{};const used=((quota.usedSpace||0)/1e9).toFixed(2);const total=((quota.userCapacity||0)/1e9).toFixed(2);row.insertCell(2).textContent=total?\`\${used}GB / \${total}GB\`:'--';const actionCell=row.insertCell(3);const delBtn=document.createElement('button');delBtn.textContent='删除';delBtn.className='delete-btn';delBtn.style.marginRight='8px';delBtn.onclick=async()=>{if(confirm(\`删除用户 "\${u.username}"？文件仍在华为云盘。\`)){await fetch(\`/api/users/\${encodeURIComponent(u.username)}\`,{method:'DELETE'});loadUsers();}};const refreshBtn=document.createElement('button');refreshBtn.textContent='刷新Token';refreshBtn.className='refresh-btn';refreshBtn.onclick=async()=>{const resp=await fetch(\`/api/users/\${encodeURIComponent(u.username)}/refresh\`,{method:'POST'});const data=await resp.json();alert(data.message||(data.success?'刷新成功':'刷新失败'));loadUsers();};actionCell.appendChild(delBtn);actionCell.appendChild(refreshBtn);}}catch(e){document.querySelector('#userTable tbody').innerHTML='<tr><td colspan="4">加载失败</td></tr>';}}async function updateServiceStatus(){try{const resp=await fetch('/api/status');const data=await resp.json();const statusSpan=document.getElementById('serviceStatus');if(data.running){statusSpan.textContent='运行中';statusSpan.className='status-badge status-running';}else{statusSpan.textContent='已停止';statusSpan.className='status-badge status-stopped';}}catch(e){console.error(e);}}document.getElementById('startServiceBtn').onclick=async()=>{try{const resp=await fetch('/api/start',{method:'POST'});const data=await resp.json();if(data.success){updateServiceStatus();showStatus('WebDAV服务启动成功','success');}else{showStatus('启动失败: '+data.error,'error');}}catch(e){showStatus('请求失败','error');}};document.getElementById('stopServiceBtn').onclick=async()=>{try{const resp=await fetch('/api/stop',{method:'POST'});const data=await resp.json();if(data.success){updateServiceStatus();showStatus('WebDAV服务已停止','success');}else{showStatus('停止失败: '+data.error,'error');}}catch(e){showStatus('请求失败','error');}};document.getElementById('addBtn').onclick=async()=>{const username=document.getElementById('webdavUsername').value.trim();const password=document.getElementById('webdavPassword').value;const authCode=document.getElementById('authCode').value.trim();if(!username||!password||!authCode){showStatus('请完整填写用户名、密码和授权码',true);return;}try{const resp=await fetch('/api/add-user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,code:authCode})});const data=await resp.json();if(resp.ok){showStatus('用户添加成功！','success');loadUsers();document.getElementById('webdavUsername').value='';document.getElementById('webdavPassword').value='';document.getElementById('authCode').value='';}else{showStatus('失败: '+data.error,'error');}}catch(e){showStatus('网络错误: '+e.message,'error');}};document.getElementById('getCodeBtn').onclick=()=>{window.open('${AUTHORIZE_URL}', '_blank', 'width=500,height=600');};document.getElementById('logoutBtn').onclick=()=>{window.location.href='/logout';};window.addEventListener('load',()=>{loadUsers();updateServiceStatus();setInterval(updateServiceStatus,5000);});</script></body></html>`);
});

adminApp.get('/api/users', requireLogin, (req, res) => {
    res.json(usersConfig.map(u => ({ username: u.username, huawei: u.huawei })));
});
adminApp.delete('/api/users/:username', requireLogin, (req, res) => {
    const username = req.params.username;
    const idx = usersConfig.findIndex(u => u.username === username);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    usersConfig.splice(idx, 1);
    saveConfig();
    delete pathCaches[userKey(username)];
    if (serverInstance && serverInstance.userManager) {
        serverInstance.userManager.removeUser(username);
        if (global._webdavUserSet) global._webdavUserSet.delete(username);
    }
    res.json({ success: true });
});
adminApp.post('/api/users/:username/refresh', requireLogin, async (req, res) => {
    const username = req.params.username;
    try {
        await refreshToken(username);
        const u = findConfigUser(username);
        if (u && u.token) {
            const info = await getHuaweiUserInfo(u.token.access_token);
            u.huawei = info;
            saveConfig();
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
adminApp.post('/api/add-user', requireLogin, async (req, res) => {
    const { username, password, code } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!code) return res.status(400).json({ error: 'Authorization code required' });
    if (findConfigUser(username)) return res.status(400).json({ error: 'User already exists' });
    try {
        const postData = QS.stringify({ grant_type: 'authorization_code', code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uri: REDIRECT_URI });
        const { raw } = await httpsRequest({
            hostname: 'oauth-login.cloud.huawei.com', port: 443, path: '/oauth2/v3/token', method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData, 'utf8') }
        }, postData);
        const result = safeJsonParse(raw);
        if (!result.success || result.data.error) throw new Error(result.data?.error_description || 'Auth failed');
        const tokenData = result.data;
        const userInfo = await getHuaweiUserInfo(tokenData.access_token);
        usersConfig.push({ username, password, token: tokenData, huawei: userInfo });
        saveConfig();
        if (serverInstance && serverInstance.userManager) {
            serverInstance.userManager.addUser(username, password, false);
            if (!global._webdavUserSet) global._webdavUserSet = new Set();
            global._webdavUserSet.add(username);
        }
        if (!pathCaches[userKey(username)]) pathCaches[userKey(username)] = new Map();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
adminApp.get('/api/status', requireLogin, (req, res) => {
    res.json({ running: isRunning });
});
adminApp.post('/api/start', requireLogin, async (req, res) => {
    try {
        if (isRunning) return res.json({ success: true, message: 'Already running' });
        await startServer();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
adminApp.post('/api/stop', requireLogin, async (req, res) => {
    try {
        if (!isRunning) return res.json({ success: true, message: 'Already stopped' });
        await stopServer();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function startAdminServer() {
    return new Promise((resolve) => {
        adminApp.listen(ADMIN_PORT, () => {
            console.log(`Admin panel started on port ${ADMIN_PORT}`);
            resolve();
        });
    });
}

async function main() {
    await startServer();
    await startAdminServer();
    console.log(`All services running. WebDAV port: ${WEBDAV_PORT}, Admin port: ${ADMIN_PORT}`);
}

if (!process.stdin.isTTY || process.env.DAEMON === '1') {
    main().catch(e => { log('Start failed: ' + e.message); process.exit(1); });
} else {
    const rl = READLINE.createInterface({ input: process.stdin, output: process.stdout });
    const ask = q => new Promise(r => rl.question(q, r));
    (async function() {
        await main();
        while (true) {
            const input = (await ask('webdav> ')).trim();
            if (!input) continue;
            const [cmd, sub] = input.split(/\s+/);
            try {
                if (cmd === 'stop') await stopServer();
                else if (cmd === 'start') await startServer();
                else if (cmd === 'status') {
                    console.log(`Running: ${isRunning}`);
                    await updateAllHuaweiInfo();
                    usersConfig.forEach(u => { console.log(`\n- ${u.username}`); if (u.huawei?.user) console.log(`  ${u.huawei.user.displayName} (${(u.huawei.storageQuota.usedSpace/1e9).toFixed(2)}GB / ${(u.huawei.storageQuota.userCapacity/1e9).toFixed(2)}GB)`); });
                } else if (cmd === 'user' && sub === 'del') {
                    let username = (await ask('WebDAV Username: ')).trim();
                    const before = usersConfig.length;
                    usersConfig = usersConfig.filter(u => normalizeUsername(u.username) !== normalizeUsername(username));
                    if (usersConfig.length === before) console.log('Not found');
                    else { delete pathCaches[userKey(username)]; saveConfig(); console.log('Deleted.'); if (isRunning) { await stopServer(); await startServer(); } }
                } else if (cmd === 'user' && sub === 'list') usersConfig.forEach(u => console.log(u.username));
                else if (cmd === 'exit') process.exit(0);
                else console.log('Commands: start, stop, status, user del, user list, exit');
            } catch (e) { console.log('Error:', e.message); }
        }
    })().catch(console.log);
}

process.on('uncaughtException', e => log('Uncaught: ' + e.message));
process.on('unhandledRejection', e => log('Unhandled: ' + e));