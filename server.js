const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Database
const db = new sqlite3.Database(path.join(__dirname, 'site.db'));

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

// Init DB
db.serialize(() => {
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
    )`, () => {
        db.run(`INSERT OR IGNORE INTO stats (id, page_views, unique_visitors) VALUES (1, 0, 0)`);
    });
});

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

    const hash = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
        [username, email, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Пользователь уже существует' });
                }
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            req.session.userId = this.lastID;
            req.session.username = username;
            req.session.userRole = 'user';
            res.json({ success: true, username, role: 'user' });
        });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }
        db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.userRole = user.role;
        res.json({ success: true, username: user.username, role: user.role });
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    db.get(`SELECT id, username, email, avatar, bio, role, created_at, last_login FROM users WHERE id = ?`,
        [req.session.userId], (err, user) => {
            if (err || !user) return res.json({ loggedIn: false });
            res.json({ loggedIn: true, ...user });
        });
});

// === COMMENTS ===

app.get('/api/comments', (req, res) => {
    db.all(`SELECT c.*, u.username, u.avatar FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.created_at DESC LIMIT 50`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка' });
        res.json(rows);
    });
});

app.post('/api/comments', requireAuth, (req, res) => {
    const { text } = req.body;
    if (!text || text.length > 500) {
        return res.status(400).json({ error: 'Комментарий 1-500 символов' });
    }
    db.run(`INSERT INTO comments (user_id, text) VALUES (?, ?)`,
        [req.session.userId, text], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка' });
            res.json({ success: true, id: this.lastID });
        });
});

app.delete('/api/comments/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    db.get(`SELECT * FROM comments WHERE id = ?`, [id], (err, comment) => {
        if (!comment) return res.status(404).json({ error: 'Не найдено' });
        if (comment.user_id !== req.session.userId && req.session.userRole !== 'admin') {
            return res.status(403).json({ error: 'Нет прав' });
        }
        db.run(`DELETE FROM comments WHERE id = ?`, [id]);
        res.json({ success: true });
    });
});

// === LIKES ===

app.post('/api/like', requireAuth, (req, res) => {
    const { target } = req.body;
    db.run(`INSERT OR IGNORE INTO likes (user_id, target) VALUES (?, ?)`,
        [req.session.userId, target], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка' });
            res.json({ success: true, liked: this.changes > 0 });
        });
});

app.delete('/api/like', requireAuth, (req, res) => {
    const { target } = req.body;
    db.run(`DELETE FROM likes WHERE user_id = ? AND target = ?`,
        [req.session.userId, target], function(err) {
            res.json({ success: true, removed: this.changes > 0 });
        });
});

app.get('/api/likes/:target', (req, res) => {
    db.get(`SELECT COUNT(*) as count FROM likes WHERE target = ?`, [req.params.target], (err, row) => {
        let liked = false;
        if (req.session.userId) {
            db.get(`SELECT id FROM likes WHERE user_id = ? AND target = ?`,
                [req.session.userId, req.params.target], (err2, like) => {
                    liked = !!like;
                    res.json({ count: row.count, liked });
                });
        } else {
            res.json({ count: row.count, liked: false });
        }
    });
});

// === MESSAGES ===

app.get('/api/messages', requireAuth, (req, res) => {
    db.all(`SELECT m.*, u.username as from_name FROM messages m
            LEFT JOIN users u ON m.from_user = u.id
            WHERE m.to_user = ? ORDER BY m.created_at DESC`,
        [req.session.userId], (err, rows) => {
            res.json(rows || []);
        });
});

app.post('/api/messages', requireAuth, (req, res) => {
    const { to_username, text } = req.body;
    db.get(`SELECT id FROM users WHERE username = ?`, [to_username], (err, user) => {
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        db.run(`INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)`,
            [req.session.userId, user.id, text]);
        res.json({ success: true });
    });
});

// === PROFILE ===

app.put('/api/profile', requireAuth, (req, res) => {
    const { bio, avatar } = req.body;
    db.run(`UPDATE users SET bio = ?, avatar = ? WHERE id = ?`,
        [bio || '', avatar || '', req.session.userId]);
    res.json({ success: true });
});

app.get('/api/user/:username', (req, res) => {
    db.get(`SELECT id, username, avatar, bio, role, created_at FROM users WHERE username = ?`,
        [req.params.username], (err, user) => {
            if (!user) return res.status(404).json({ error: 'Не найден' });
            db.get(`SELECT COUNT(*) as count FROM comments WHERE user_id = ?`, [user.id], (err2, row) => {
                user.comments_count = row.count;
                res.json(user);
            });
        });
});

// === STATS ===

app.get('/api/stats', (req, res) => {
    db.get(`SELECT * FROM stats WHERE id = 1`, (err, row) => {
        db.get(`SELECT COUNT(*) as users FROM users`, (err2, u) => {
            db.get(`SELECT COUNT(*) as comments FROM comments`, (err3, c) => {
                res.json({
                    page_views: row ? row.page_views : 0,
                    users: u ? u.users : 0,
                    comments: c ? c.comments : 0
                });
            });
        });
    });
});

app.post('/api/view', (req, res) => {
    db.run(`UPDATE stats SET page_views = page_views + 1 WHERE id = 1`);
    res.json({ success: true });
});

// === ADMIN ===

app.get('/api/admin/users', requireAdmin, (req, res) => {
    db.all(`SELECT id, username, email, role, created_at, last_login FROM users`, [], (err, rows) => {
        res.json(rows || []);
    });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    db.run(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id]);
    res.json({ success: true });
});

app.put('/api/admin/users/:id/role', requireAdmin, (req, res) => {
    const { role } = req.body;
    if (!['user', 'admin', 'banned'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
    db.run(`UPDATE users SET role = ? WHERE id = ?`, [role, req.params.id]);
    res.json({ success: true });
});

app.get('/api/admin/banned', requireAdmin, (req, res) => {
    db.all(`SELECT id, username, email, created_at FROM users WHERE role = 'banned'`, [], (err, rows) => {
        res.json(rows || []);
    });
});

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
});
