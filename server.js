const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'site.db');

let db;

function saveDb() {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function dbRun(sql, params = []) {
    db.run(sql, params);
    saveDb();
}

function dbGet(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    let row = null;
    if (stmt.step()) {
        row = stmt.getAsObject();
    }
    stmt.free();
    return row;
}

function dbAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
        rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
}

async function start() {
    const SQL = await initSqlJs();

    if (fs.existsSync(DB_PATH)) {
        const buf = fs.readFileSync(DB_PATH);
        db = new SQL.Database(buf);
    } else {
        db = new SQL.Database();
    }

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, target),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        text TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (from_user) REFERENCES users(id),
        FOREIGN KEY (to_user) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page_views INTEGER DEFAULT 0,
        unique_visitors INTEGER DEFAULT 0
    )`);

    dbRun(`INSERT OR IGNORE INTO stats (id, page_views, unique_visitors) VALUES (1, 0, 0)`);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session.userId) return next();
    res.status(401).json({ error: 'Необходима авторизация' });
}

function requireAdmin(req, res, next) {
    if (req.session.userRole === 'admin') return next();
    res.status(403).json({ error: 'Нет прав администратора' });
}

// === AUTH ===

app.post('/api/register', (req, res) => {
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

    try {
        const existing = dbGet(`SELECT id FROM users WHERE username = ? OR email = ?`, [username, email]);
        if (existing) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        const hash = bcrypt.hashSync(password, 10);
        dbRun(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hash]);
        const user = dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
        req.session.userId = user.id;
        req.session.username = username;
        req.session.userRole = 'user';
        res.json({ success: true, username, role: 'user' });
    } catch (e) {
        return res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = dbGet(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    dbRun(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = user.role;
    res.json({ success: true, username: user.username, role: user.role });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = dbGet(`SELECT id, username, email, avatar, bio, role, created_at, last_login FROM users WHERE id = ?`,
        [req.session.userId]);
    if (!user) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, ...user });
});

// === COMMENTS ===

app.get('/api/comments', (req, res) => {
    const rows = dbAll(`SELECT c.*, u.username, u.avatar FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC LIMIT 50`);
    res.json(rows);
});

app.post('/api/comments', requireAuth, (req, res) => {
    const { text } = req.body;
    if (!text || text.length > 500) {
        return res.status(400).json({ error: 'Комментарий 1-500 символов' });
    }
    dbRun(`INSERT INTO comments (user_id, text) VALUES (?, ?)`, [req.session.userId, text]);
    const row = dbGet(`SELECT last_insert_rowid() as id`);
    res.json({ success: true, id: row.id });
});

app.delete('/api/comments/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    const comment = dbGet(`SELECT * FROM comments WHERE id = ?`, [id]);
    if (!comment) return res.status(404).json({ error: 'Не найдено' });
    if (comment.user_id !== req.session.userId && req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Нет прав' });
    }
    dbRun(`DELETE FROM comments WHERE id = ?`, [id]);
    res.json({ success: true });
});

// === LIKES ===

app.post('/api/like', requireAuth, (req, res) => {
    const { target } = req.body;
    const existing = dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
        [req.session.userId, target]);
    if (!existing) {
        dbRun(`INSERT INTO likes (user_id, target) VALUES (?, ?)`, [req.session.userId, target]);
        res.json({ success: true, liked: true });
    } else {
        res.json({ success: true, liked: false });
    }
});

app.delete('/api/like', requireAuth, (req, res) => {
    const { target } = req.body;
    const existing = dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
        [req.session.userId, target]);
    dbRun(`DELETE FROM likes WHERE user_id = ? AND target = ?`, [req.session.userId, target]);
    res.json({ success: true, removed: !!existing });
});

app.get('/api/likes/:target', (req, res) => {
    const row = dbGet(`SELECT COUNT(*) as count FROM likes WHERE target = ?`, [req.params.target]);
    let liked = false;
    if (req.session.userId) {
        const like = dbGet(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
            [req.session.userId, req.params.target]);
        liked = !!like;
    }
    res.json({ count: row ? row.count : 0, liked });
});

// === MESSAGES ===

app.get('/api/messages', requireAuth, (req, res) => {
    const rows = dbAll(`SELECT m.*, u.username as from_name FROM messages m
            LEFT JOIN users u ON m.from_user = u.id
            WHERE m.to_user = ? ORDER BY m.created_at DESC`,
        [req.session.userId]);
    res.json(rows || []);
});

app.post('/api/messages', requireAuth, (req, res) => {
    const { to_username, text } = req.body;
    const user = dbGet(`SELECT id FROM users WHERE username = ?`, [to_username]);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    dbRun(`INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)`,
        [req.session.userId, user.id, text]);
    res.json({ success: true });
});

// === PROFILE ===

app.put('/api/profile', requireAuth, (req, res) => {
    const { bio, avatar } = req.body;
    dbRun(`UPDATE users SET bio = ?, avatar = ? WHERE id = ?`,
        [bio || '', avatar || '', req.session.userId]);
    res.json({ success: true });
});

app.get('/api/user/:username', (req, res) => {
    const user = dbGet(`SELECT id, username, avatar, bio, role, created_at FROM users WHERE username = ?`,
        [req.params.username]);
    if (!user) return res.status(404).json({ error: 'Не найден' });
    const row = dbGet(`SELECT COUNT(*) as count FROM comments WHERE user_id = ?`, [user.id]);
    user.comments_count = row ? row.count : 0;
    res.json(user);
});

// === STATS ===

app.get('/api/stats', (req, res) => {
    const row = dbGet(`SELECT * FROM stats WHERE id = 1`);
    const u = dbGet(`SELECT COUNT(*) as users FROM users`);
    const c = dbGet(`SELECT COUNT(*) as comments FROM comments`);
    res.json({
        page_views: row ? row.page_views : 0,
        users: u ? u.users : 0,
        comments: c ? c.comments : 0
    });
});

app.post('/api/view', (req, res) => {
    dbRun(`UPDATE stats SET page_views = page_views + 1 WHERE id = 1`);
    res.json({ success: true });
});

// === ADMIN ===

app.get('/api/admin/users', requireAdmin, (req, res) => {
    const rows = dbAll(`SELECT id, username, email, role, created_at, last_login FROM users`);
    res.json(rows || []);
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    dbRun(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id]);
    res.json({ success: true });
});

app.put('/api/admin/users/:id/role', requireAdmin, (req, res) => {
    const { role } = req.body;
    if (!['user', 'admin', 'banned'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
    dbRun(`UPDATE users SET role = ? WHERE id = ?`, [role, req.params.id]);
    res.json({ success: true });
});

app.get('/api/admin/banned', requireAdmin, (req, res) => {
    const rows = dbAll(`SELECT id, username, email, created_at FROM users WHERE role = 'banned'`);
    res.json(rows || []);
});

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

start().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Ошибка запуска:', err);
    process.exit(1);
});
