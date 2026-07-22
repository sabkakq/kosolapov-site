const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const HAS_PG = !!process.env.DATABASE_URL;

let pool = null;
let sqlDb = null;

// === HELPERS ===

function toPg(sql, params) {
    let i = 0;
    return { sql: sql.replace(/\?/g, () => `$${++i}`), params };
}

function saveDb() {
    if (!sqlDb) return;
    const data = sqlDb.export();
    fs.writeFileSync(path.join(__dirname, 'site.db'), Buffer.from(data));
}

// === UNIFORM DB HELPERS ===

async function dbRun(sql, params = []) {
    if (HAS_PG) {
        const pg = toPg(sql, params);
        const client = await pool.connect();
        try {
            await client.query(pg.sql, pg.params);
        } finally {
            client.release();
        }
    } else {
        sqlDb.run(sql, params);
        saveDb();
    }
}

async function dbGet(sql, params = []) {
    if (HAS_PG) {
        const pg = toPg(sql, params);
        const client = await pool.connect();
        try {
            const res = await client.query(pg.sql, pg.params);
            return res.rows[0] || null;
        } finally {
            client.release();
        }
    } else {
        const stmt = sqlDb.prepare(sql);
        stmt.bind(params);
        let row = null;
        if (stmt.step()) {
            const cols = stmt.getColumnNames();
            const vals = stmt.get();
            row = {};
            cols.forEach((c, i) => row[c] = vals[i]);
        }
        stmt.free();
        return row;
    }
}

async function dbAll(sql, params = []) {
    if (HAS_PG) {
        const pg = toPg(sql, params);
        const client = await pool.connect();
        try {
            const res = await client.query(pg.sql, pg.params);
            return res.rows;
        } finally {
            client.release();
        }
    } else {
        const stmt = sqlDb.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) {
            const cols = stmt.getColumnNames();
            const vals = stmt.get();
            const row = {};
            cols.forEach((c, i) => row[c] = vals[i]);
            rows.push(row);
        }
        stmt.free();
        return rows;
    }
}

async function dbInsert(sql, params = []) {
    if (HAS_PG) {
        const pg = toPg(sql + ' RETURNING id', params);
        const client = await pool.connect();
        try {
            const res = await client.query(pg.sql, pg.params);
            return res.rows[0].id;
        } finally {
            client.release();
        }
    } else {
        sqlDb.run(sql, params);
        saveDb();
        const result = sqlDb.exec("SELECT last_insert_rowid() as id");
        return result[0].values[0][0];
    }
}

// === INIT DB ===

async function initDB() {
    if (HAS_PG) {
        const { Pool } = require('pg');
        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }
        });

        await dbRun(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(20) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )`);
        await dbRun(`CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await dbRun(`CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            target TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, target)
        )`);
        await dbRun(`CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            from_user INTEGER REFERENCES users(id),
            to_user INTEGER REFERENCES users(id),
            text TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await dbRun(`CREATE TABLE IF NOT EXISTS stats (
            id SERIAL PRIMARY KEY,
            page_views INTEGER DEFAULT 0,
            unique_visitors INTEGER DEFAULT 0
        )`);
        await dbRun(`INSERT INTO stats (page_views, unique_visitors) SELECT 0, 0 WHERE NOT EXISTS (SELECT 1 FROM stats WHERE id = 1)`);
        await dbRun(`CREATE TABLE IF NOT EXISTS user_sessions (
            sid VARCHAR NOT NULL COLLATE "default",
            sess JSONB NOT NULL,
            expire TIMESTAMP(6) NOT NULL,
            PRIMARY KEY (sid)
        )`);
        await dbRun(`CREATE INDEX IF NOT EXISTS IDX_user_sessions_expire ON user_sessions (expire)`);
    } else {
        const initSqlJs = require('sql.js');
        const SQL = await initSqlJs();
        const dbPath = path.join(__dirname, 'site.db');
        if (fs.existsSync(dbPath)) {
            sqlDb = new SQL.Database(new Uint8Array(fs.readFileSync(dbPath)));
        } else {
            sqlDb = new SQL.Database();
        }

        sqlDb.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT
        )`);
        sqlDb.run(`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            text TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )`);
        sqlDb.run(`CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            target TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, target)
        )`);
        sqlDb.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user INTEGER REFERENCES users(id),
            to_user INTEGER REFERENCES users(id),
            text TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )`);
        sqlDb.run(`CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_views INTEGER DEFAULT 0,
            unique_visitors INTEGER DEFAULT 0
        )`);
        sqlDb.run(`INSERT INTO stats (page_views, unique_visitors) SELECT 0, 0 WHERE NOT EXISTS (SELECT 1 FROM stats WHERE id = 1)`);
        saveDb();
    }
}

// === EXPRESS MIDDLEWARE ===

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// === SESSION MIDDLEWARE ===

const sessionConfig = {
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
};

if (HAS_PG) {
    const pgSession = require('connect-pg-simple')(session);
    sessionConfig.store = new pgSession({ pool, tableName: 'user_sessions' });
}

app.use(session(sessionConfig));

// === AUTH MIDDLEWARE ===

function requireAuth(req, res, next) {
    if (req.session.userId) return next();
    res.status(401).json({ error: 'Необходима авторизация' });
}

function requireAdmin(req, res, next) {
    if (req.session.userRole === 'admin') return next();
    res.status(403).json({ error: 'Нет прав администратора' });
}

// === ROUTES: AUTH ===

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Заполните все поля' });
        }
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Имя пользователя 3-20 символов' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Пароль минимум 6 символов' });
        }

        const existing = await dbGet(`SELECT id FROM users WHERE username = ? OR email = ?`, [username, email]);
        if (existing) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        const hash = await bcrypt.hash(password, 10);
        const id = await dbInsert(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hash]);
        req.session.userId = id;
        req.session.username = username;
        req.session.userRole = 'user';
        res.json({ success: true, username, role: 'user' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await dbGet(`SELECT * FROM users WHERE username = ?`, [username]);
        if (!user) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }
        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }
        await dbRun(`UPDATE users SET last_login = ? WHERE id = ?`, [new Date().toISOString(), user.id]);
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.userRole = user.role;
        res.json({ success: true, username: user.username, role: user.role });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = await dbGet(`SELECT id, username, email, avatar, bio, role, created_at, last_login FROM users WHERE id = ?`,
        [req.session.userId]);
    if (!user) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, ...user });
});

// === ROUTES: COMMENTS ===

app.get('/api/comments', async (req, res) => {
    try {
        const rows = await dbAll(`SELECT c.id, c.user_id, c.text, c.created_at, u.username, u.avatar FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC LIMIT 50`);
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/comments', requireAuth, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || text.length > 500) {
            return res.status(400).json({ error: 'Комментарий 1-500 символов' });
        }
        const id = await dbInsert(`INSERT INTO comments (user_id, text) VALUES (?, ?)`, [req.session.userId, text]);
        res.json({ success: true, id });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
    try {
        const comment = await dbGet(`SELECT * FROM comments WHERE id = ?`, [req.params.id]);
        if (!comment) return res.status(404).json({ error: 'Не найдено' });
        if (comment.user_id !== req.session.userId && req.session.userRole !== 'admin') {
            return res.status(403).json({ error: 'Нет прав' });
        }
        await dbRun(`DELETE FROM comments WHERE id = ?`, [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === ROUTES: LIKES ===

app.post('/api/like', requireAuth, async (req, res) => {
    try {
        const { target } = req.body;
        const existing = await dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
            [req.session.userId, target]);
        if (!existing) {
            await dbRun(`INSERT INTO likes (user_id, target) VALUES (?, ?)`, [req.session.userId, target]);
            res.json({ success: true, liked: true });
        } else {
            res.json({ success: true, liked: false });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/like', requireAuth, async (req, res) => {
    try {
        const { target } = req.body;
        const existing = await dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
            [req.session.userId, target]);
        await dbRun(`DELETE FROM likes WHERE user_id = ? AND target = ?`, [req.session.userId, target]);
        res.json({ success: true, removed: !!existing });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/likes/:target', async (req, res) => {
    try {
        const row = await dbGet(`SELECT COUNT(*) as count FROM likes WHERE target = ?`, [req.params.target]);
        let liked = false;
        if (req.session.userId) {
            const like = await dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
                [req.session.userId, req.params.target]);
            liked = !!like;
        }
        res.json({ count: row ? Number(row.count) : 0, liked });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === ROUTES: MESSAGES ===

app.get('/api/messages', requireAuth, async (req, res) => {
    try {
        const rows = await dbAll(`SELECT m.*, u.username as from_name FROM messages m
            LEFT JOIN users u ON m.from_user = u.id
            WHERE m.to_user = ? ORDER BY m.created_at DESC`,
            [req.session.userId]);
        res.json(rows || []);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/messages', requireAuth, async (req, res) => {
    try {
        const { to_username, text } = req.body;
        const user = await dbGet(`SELECT id FROM users WHERE username = ?`, [to_username]);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        await dbRun(`INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)`,
            [req.session.userId, user.id, text]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === ROUTES: PROFILE ===

app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const { bio, avatar } = req.body;
        await dbRun(`UPDATE users SET bio = ?, avatar = ? WHERE id = ?`,
            [bio || '', avatar || '', req.session.userId]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/user/:username', async (req, res) => {
    try {
        const user = await dbGet(`SELECT id, username, avatar, bio, role, created_at FROM users WHERE username = ?`,
            [req.params.username]);
        if (!user) return res.status(404).json({ error: 'Не найден' });
        const row = await dbGet(`SELECT COUNT(*) as count FROM comments WHERE user_id = ?`, [user.id]);
        user.comments_count = row ? Number(row.count) : 0;
        res.json(user);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === ROUTES: STATS ===

app.get('/api/stats', async (req, res) => {
    try {
        const row = await dbGet(`SELECT * FROM stats WHERE id = 1`);
        const u = await dbGet(`SELECT COUNT(*) as count FROM users`);
        const c = await dbGet(`SELECT COUNT(*) as count FROM comments`);
        res.json({
            page_views: row ? row.page_views : 0,
            users: u ? Number(u.count) : 0,
            comments: c ? Number(c.count) : 0
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/view', async (req, res) => {
    try {
        await dbRun(`UPDATE stats SET page_views = page_views + 1 WHERE id = 1`);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === ROUTES: ADMIN ===

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const rows = await dbAll(`SELECT id, username, email, role, created_at, last_login FROM users`);
        res.json(rows || []);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        await dbRun(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/admin/users/:id/role', requireAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        if (!['user', 'admin', 'banned'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
        await dbRun(`UPDATE users SET role = ? WHERE id = ?`, [role, req.params.id]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/admin/banned', requireAdmin, async (req, res) => {
    try {
        const rows = await dbAll(`SELECT id, username, email, created_at FROM users WHERE role = 'banned'`);
        res.json(rows || []);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// === STATIC ===

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// === STARTUP ===

initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Сервер запущен (${HAS_PG ? 'PostgreSQL' : 'SQLite'}): http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Ошибка запуска:', err);
    process.exit(1);
});
