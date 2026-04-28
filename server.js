const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'quicknotes-secret-change-in-prod';

// Database setup
const db = new Database('./data/notes.db');
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  
  CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
`);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Auth middleware
const auth = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Auth routes
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)');
    const result = stmt.run(email, hash, name || email.split('@')[0]);
    
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, user: { id: result.lastInsertRowid, email, name } });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(req.user.id);
  res.json({ user });
});

// Notes routes
app.get('/api/notes', auth, (req, res) => {
  const notes = db.prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC').all(req.user.id);
  res.json({ notes });
});

app.post('/api/notes', auth, (req, res) => {
  const { title, content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });
  
  const stmt = db.prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)');
  const result = stmt.run(req.user.id, title || '', content);
  
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(result.lastInsertRowid);
  res.json({ note });
});

app.put('/api/notes/:id', auth, (req, res) => {
  const { title, content } = req.body;
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  
  db.prepare('UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(title ?? note.title, content ?? note.content, req.params.id);
  
  const updated = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  res.json({ note: updated });
});

app.delete('/api/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  
  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Serve app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`QuickNotes running on port ${PORT}`);
});
