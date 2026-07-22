const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function dbRun(sql, params = []) {
    const client = await pool.connect();
    try {
        await client.query(sql, params);
    } finally {
        client.release();
    }
}

async function dbGet(sql, params = []) {
    const client = await pool.connect();
    try {
        const res = await client.query(sql, params);
        return res.rows[0] || null;
    } finally {
        client.release();
    }
}

async function dbAll(sql, params = []) {
    const client = await pool.connect();
    try {
        const res = await client.query(sql, params);
        return res.rows;
    } finally {
        client.release();
    }
}

async function initDB() {
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
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
    store: new pgSession({ pool, tableName: 'user_sessions' }),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
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

app.post('/api/register', async (req, res) => {
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
        const existing = await dbGet(`SELECT id FROM users WHERE username = $1 OR email = $2`, [username, email]);
        if (existing) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        const hash = await bcrypt.hash(password, 10);
        const result = await dbGet(`INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id`, [username, email, hash]);
        req.session.userId = result.id;
        req.session.username = username;
        req.session.userRole = 'user';
        res.json({ success: true, username, role: 'user' });
    } catch (e) {
        return res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await dbGet(`SELECT * FROM users WHERE username = $1`, [username]);
    if (!user) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    if (!(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    await dbRun(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`, [user.id]);
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = user.role;
    res.json({ success: true, username: user.username, role: user.role });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = await dbGet(`SELECT id, username, email, avatar, bio, role, created_at, last_login FROM users WHERE id = $1`,
        [req.session.userId]);
    if (!user) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, ...user });
});

// === COMMENTS ===

app.get('/api/comments', async (req, res) => {
    const rows = await dbAll(`SELECT c.id, c.user_id, c.text, c.created_at, u.username, u.avatar FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC LIMIT 50`);
    res.json(rows);
});

app.post('/api/comments', requireAuth, async (req, res) => {
    const { text } = req.body;
    if (!text || text.length > 500) {
        return res.status(400).json({ error: 'Комментарий 1-500 символов' });
    }
    const result = await dbGet(`INSERT INTO comments (user_id, text) VALUES ($1, $2) RETURNING id`, [req.session.userId, text]);
    res.json({ success: true, id: result.id });
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
    const id = req.params.id;
    const comment = await dbGet(`SELECT * FROM comments WHERE id = $1`, [id]);
    if (!comment) return res.status(404).json({ error: 'Не найдено' });
    if (comment.user_id !== req.session.userId && req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Нет прав' });
    }
    await dbRun(`DELETE FROM comments WHERE id = $1`, [id]);
    res.json({ success: true });
});

// === LIKES ===

app.post('/api/like', requireAuth, async (req, res) => {
    const { target } = req.body;
    const existing = await dbGet(`SELECT id FROM likes WHERE user_id = $1 AND target = $2`,
        [req.session.userId, target]);
    if (!existing) {
        await dbRun(`INSERT INTO likes (user_id, target) VALUES ($1, $2)`, [req.session.userId, target]);
        res.json({ success: true, liked: true });
    } else {
        res.json({ success: true, liked: false });
    }
});

app.delete('/api/like', requireAuth, async (req, res) => {
    const { target } = req.body;
    const existing = await dbGet(`SELECT id FROM likes WHERE user_id = $1 AND target = $2`,
        [req.session.userId, target]);
    await dbRun(`DELETE FROM likes WHERE user_id = $1 AND target = $2`, [req.session.userId, target]);
    res.json({ success: true, removed: !!existing });
});

app.get('/api/likes/:target', async (req, res) => {
    const row = await dbGet(`SELECT COUNT(*)::int as count FROM likes WHERE target = $1`, [req.params.target]);
    let liked = false;
    if (req.session.userId) {
        const like = await dbGet(`SELECT id FROM likes WHERE user_id = $1 AND target = $2`,
            [req.session.userId, req.params.target]);
        liked = !!like;
    }
    res.json({ count: row ? row.count : 0, liked });
});

// === MESSAGES ===

app.get('/api/messages', requireAuth, async (req, res) => {
    const rows = await dbAll(`SELECT m.*, u.username as from_name FROM messages m
            LEFT JOIN users u ON m.from_user = u.id
            WHERE m.to_user = $1 ORDER BY m.created_at DESC`,
        [req.session.userId]);
    res.json(rows || []);
});

app.post('/api/messages', requireAuth, async (req, res) => {
    const { to_username, text } = req.body;
    const user = await dbGet(`SELECT id FROM users WHERE username = $1`, [to_username]);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    await dbRun(`INSERT INTO messages (from_user, to_user, text) VALUES ($1, $2, $3)`,
        [req.session.userId, user.id, text]);
    res.json({ success: true });
});

// === PROFILE ===

app.put('/api/profile', requireAuth, async (req, res) => {
    const { bio, avatar } = req.body;
    await dbRun(`UPDATE users SET bio = $1, avatar = $2 WHERE id = $3`,
        [bio || '', avatar || '', req.session.userId]);
    res.json({ success: true });
});

app.get('/api/user/:username', async (req, res) => {
    const user = await dbGet(`SELECT id, username, avatar, bio, role, created_at FROM users WHERE username = $1`,
        [req.params.username]);
    if (!user) return res.status(404).json({ error: 'Не найден' });
    const row = await dbGet(`SELECT COUNT(*)::int as count FROM comments WHERE user_id = $1`, [user.id]);
    user.comments_count = row ? row.count : 0;
    res.json(user);
});

// === STATS ===

app.get('/api/stats', async (req, res) => {
    const row = await dbGet(`SELECT * FROM stats WHERE id = 1`);
    const u = await dbGet(`SELECT COUNT(*)::int as users FROM users`);
    const c = await dbGet(`SELECT COUNT(*)::int as comments FROM comments`);
    res.json({
        page_views: row ? row.page_views : 0,
        users: u ? u.users : 0,
        comments: c ? c.comments : 0
    });
});

app.post('/api/view', async (req, res) => {
    await dbRun(`UPDATE stats SET page_views = page_views + 1 WHERE id = 1`);
    res.json({ success: true });
});

// === ADMIN ===

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    const rows = await dbAll(`SELECT id, username, email, role, created_at, last_login FROM users`);
    res.json(rows || []);
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    await dbRun(`DELETE FROM users WHERE id = $1 AND role != 'admin'`, [req.params.id]);
    res.json({ success: true });
});

app.put('/api/admin/users/:id/role', requireAdmin, async (req, res) => {
    const { role } = req.body;
    if (!['user', 'admin', 'banned'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
    await dbRun(`UPDATE users SET role = $1 WHERE id = $2`, [role, req.params.id]);
    res.json({ success: true });
});

app.get('/api/admin/banned', requireAdmin, async (req, res) => {
    const rows = await dbAll(`SELECT id, username, email, created_at FROM users WHERE role = 'banned'`);
    res.json(rows || []);
});

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Ошибка запуска:', err);
    process.exit(1);
});
