const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'quicknotes-secret-change-in-prod';
const AI_API_KEY = process.env.AI_API_KEY || process.env.GROQ_API_KEY || process.env.AZURE_OPENAI_API_KEY || '';
const AI_BASE_URL = process.env.AI_BASE_URL || process.env.AZURE_OPENAI_ENDPOINT || 'https://api.groq.com/openai/v1';
const AI_MODEL = process.env.AI_MODEL || 'gpt-4o';
const AI_PROVIDER = process.env.AI_PROVIDER || (AI_BASE_URL.includes('azure') ? 'azure' : 'openai');

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
  
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    color TEXT DEFAULT '#6366f1',
    icon TEXT DEFAULT '📁',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    group_id INTEGER,
    title TEXT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
  );
  
  CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
  CREATE INDEX IF NOT EXISTS idx_notes_group ON notes(group_id);
  CREATE INDEX IF NOT EXISTS idx_groups_user ON groups(user_id);
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
    
    // Create default "General" group for new user
    db.prepare('INSERT INTO groups (user_id, name, color, icon) VALUES (?, ?, ?, ?)')
      .run(result.lastInsertRowid, 'General', '#6366f1', '📝');
    
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

// Groups routes
app.get('/api/groups', auth, (req, res) => {
  const groups = db.prepare('SELECT * FROM groups WHERE user_id = ? ORDER BY name').all(req.user.id);
  // Add note count to each group
  const groupsWithCount = groups.map(g => {
    const count = db.prepare('SELECT COUNT(*) as count FROM notes WHERE group_id = ?').get(g.id);
    return { ...g, noteCount: count.count };
  });
  // Add ungrouped count
  const ungroupedCount = db.prepare('SELECT COUNT(*) as count FROM notes WHERE user_id = ? AND group_id IS NULL').get(req.user.id);
  res.json({ groups: groupsWithCount, ungroupedCount: ungroupedCount.count });
});

app.post('/api/groups', auth, (req, res) => {
  const { name, color, icon } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  
  const stmt = db.prepare('INSERT INTO groups (user_id, name, color, icon) VALUES (?, ?, ?, ?)');
  const result = stmt.run(req.user.id, name, color || '#6366f1', icon || '📁');
  
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(result.lastInsertRowid);
  res.json({ group: { ...group, noteCount: 0 } });
});

app.put('/api/groups/:id', auth, (req, res) => {
  const { name, color, icon } = req.body;
  const group = db.prepare('SELECT * FROM groups WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  
  db.prepare('UPDATE groups SET name = ?, color = ?, icon = ? WHERE id = ?')
    .run(name ?? group.name, color ?? group.color, icon ?? group.icon, req.params.id);
  
  const updated = db.prepare('SELECT * FROM groups WHERE id = ?').get(req.params.id);
  const count = db.prepare('SELECT COUNT(*) as count FROM notes WHERE group_id = ?').get(req.params.id);
  res.json({ group: { ...updated, noteCount: count.count } });
});

app.delete('/api/groups/:id', auth, (req, res) => {
  const group = db.prepare('SELECT * FROM groups WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  
  // Move notes to ungrouped instead of deleting
  db.prepare('UPDATE notes SET group_id = NULL WHERE group_id = ?').run(req.params.id);
  db.prepare('DELETE FROM groups WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Notes routes
app.get('/api/notes', auth, (req, res) => {
  const { group_id, search } = req.query;
  
  let query = 'SELECT n.*, g.name as group_name, g.color as group_color, g.icon as group_icon FROM notes n LEFT JOIN groups g ON n.group_id = g.id WHERE n.user_id = ?';
  const params = [req.user.id];
  
  if (group_id === 'ungrouped') {
    query += ' AND n.group_id IS NULL';
  } else if (group_id) {
    query += ' AND n.group_id = ?';
    params.push(group_id);
  }
  
  if (search) {
    query += ' AND (n.content LIKE ? OR n.title LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  
  query += ' ORDER BY n.updated_at DESC';
  
  const notes = db.prepare(query).all(...params);
  res.json({ notes });
});

app.post('/api/notes', auth, (req, res) => {
  const { title, content, group_id } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });
  
  // Verify group belongs to user if provided
  if (group_id) {
    const group = db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(group_id, req.user.id);
    if (!group) return res.status(400).json({ error: 'Invalid group' });
  }
  
  const stmt = db.prepare('INSERT INTO notes (user_id, group_id, title, content) VALUES (?, ?, ?, ?)');
  const result = stmt.run(req.user.id, group_id || null, title || '', content);
  
  const note = db.prepare('SELECT n.*, g.name as group_name, g.color as group_color, g.icon as group_icon FROM notes n LEFT JOIN groups g ON n.group_id = g.id WHERE n.id = ?').get(result.lastInsertRowid);
  res.json({ note });
});

app.put('/api/notes/:id', auth, (req, res) => {
  const { title, content, group_id } = req.body;
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  
  // Verify group belongs to user if provided
  if (group_id) {
    const group = db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(group_id, req.user.id);
    if (!group) return res.status(400).json({ error: 'Invalid group' });
  }
  
  db.prepare('UPDATE notes SET title = ?, content = ?, group_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(title ?? note.title, content ?? note.content, group_id === undefined ? note.group_id : group_id, req.params.id);
  
  const updated = db.prepare('SELECT n.*, g.name as group_name, g.color as group_color, g.icon as group_icon FROM notes n LEFT JOIN groups g ON n.group_id = g.id WHERE n.id = ?').get(req.params.id);
  res.json({ note: updated });
});

app.delete('/api/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  
  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// AI routes
app.post('/api/ai/improve', auth, async (req, res) => {
  if (!AI_API_KEY) {
    return res.status(503).json({ error: 'AI not configured' });
  }
  
  const { text, action } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  
  const prompts = {
    improve: 'Improve this text. Make it clearer, more professional, and fix any errors. Keep the same meaning and language. Return ONLY the improved text, nothing else.',
    fix: 'Fix any spelling, grammar, and punctuation errors in this text. Keep the same meaning and language. Return ONLY the corrected text, nothing else.',
    shorten: 'Make this text shorter and more concise while keeping the key information. Return ONLY the shortened text, nothing else.',
    expand: 'Expand this text with more detail and context while keeping the same tone. Return ONLY the expanded text, nothing else.',
    professional: 'Rewrite this text in a professional business tone. Return ONLY the rewritten text, nothing else.',
  };
  
  const systemPrompt = prompts[action] || prompts.improve;
  
  try {
    // Build URL and headers based on provider
    let url, headers;
    if (AI_PROVIDER === 'azure') {
      // Azure OpenAI format - check if URL already has the full path
      if (AI_BASE_URL.includes('/chat/completions')) {
        url = AI_BASE_URL;
      } else if (AI_BASE_URL.includes('/deployments/')) {
        url = `${AI_BASE_URL}/chat/completions?api-version=2025-01-01-preview`;
      } else {
        url = `${AI_BASE_URL}/openai/deployments/${AI_MODEL}/chat/completions?api-version=2025-01-01-preview`;
      }
      headers = {
        'api-key': AI_API_KEY,
        'Content-Type': 'application/json',
      };
    } else {
      // OpenAI/Groq compatible format
      url = `${AI_BASE_URL}/chat/completions`;
      headers = {
        'Authorization': `Bearer ${AI_API_KEY}`,
        'Content-Type': 'application/json',
      };
    }
    }
    
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: AI_MODEL,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: text }
        ],
        max_tokens: 2000,
        temperature: 0.7,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      console.error('AI error:', err);
      return res.status(500).json({ error: 'AI request failed' });
    }
    
    const data = await response.json();
    const result = data.choices?.[0]?.message?.content?.trim();
    
    if (!result) {
      return res.status(500).json({ error: 'No response from AI' });
    }
    
    res.json({ result });
  } catch (e) {
    console.error('AI error:', e.message);
    res.status(500).json({ error: 'AI request failed' });
  }
});

app.get('/api/ai/status', auth, (req, res) => {
  res.json({ enabled: !!AI_API_KEY });
});

// Serve app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`QuickNotes running on port ${PORT}`);
});
