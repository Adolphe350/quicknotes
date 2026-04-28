const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'quicknotes-secret-change-in-prod';

// Default AI config from env (can be overridden per-user)
const DEFAULT_AI_API_KEY = process.env.AI_API_KEY || process.env.GROQ_API_KEY || process.env.AZURE_OPENAI_API_KEY || '';
const DEFAULT_AI_BASE_URL = process.env.AI_BASE_URL || process.env.AZURE_OPENAI_ENDPOINT || 'https://api.groq.com/openai/v1';
const DEFAULT_AI_MODEL = process.env.AI_MODEL || 'gpt-4o';
const DEFAULT_AI_PROVIDER = process.env.AI_PROVIDER || (DEFAULT_AI_BASE_URL.includes('azure') ? 'azure' : 'openai');

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
  
  CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    default_group_id INTEGER,
    ai_provider TEXT DEFAULT 'openai',
    ai_model TEXT,
    ai_api_key TEXT,
    ai_base_url TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (default_group_id) REFERENCES groups(id) ON DELETE SET NULL
  );
  
  CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
  CREATE INDEX IF NOT EXISTS idx_notes_group ON notes(group_id);
  CREATE INDEX IF NOT EXISTS idx_groups_user ON groups(user_id);
`);

// Add settings table if upgrading from older version
try {
  db.exec(`ALTER TABLE user_settings ADD COLUMN ai_provider TEXT DEFAULT 'openai'`);
} catch(e) {}
try {
  db.exec(`ALTER TABLE user_settings ADD COLUMN ai_model TEXT`);
} catch(e) {}
try {
  db.exec(`ALTER TABLE user_settings ADD COLUMN ai_api_key TEXT`);
} catch(e) {}
try {
  db.exec(`ALTER TABLE user_settings ADD COLUMN ai_base_url TEXT`);
} catch(e) {}

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

// Get user's AI config (user settings override env defaults)
function getUserAIConfig(userId) {
  const settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(userId);
  return {
    apiKey: settings?.ai_api_key || DEFAULT_AI_API_KEY,
    baseUrl: settings?.ai_base_url || DEFAULT_AI_BASE_URL,
    model: settings?.ai_model || DEFAULT_AI_MODEL,
    provider: settings?.ai_provider || DEFAULT_AI_PROVIDER
  };
}

// Auth routes
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)');
    const result = stmt.run(email, hash, name || email.split('@')[0]);
    
    // Create default "General" group for new user
    const groupResult = db.prepare('INSERT INTO groups (user_id, name, color, icon) VALUES (?, ?, ?, ?)')
      .run(result.lastInsertRowid, 'General', '#6366f1', '📝');
    
    // Create settings with default group
    db.prepare('INSERT INTO user_settings (user_id, default_group_id) VALUES (?, ?)')
      .run(result.lastInsertRowid, groupResult.lastInsertRowid);
    
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

// Settings routes
app.get('/api/settings', auth, (req, res) => {
  let settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(req.user.id);
  
  // Create settings if not exists
  if (!settings) {
    db.prepare('INSERT INTO user_settings (user_id) VALUES (?)').run(req.user.id);
    settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(req.user.id);
  }
  
  // Get AI status
  const aiConfig = getUserAIConfig(req.user.id);
  const hasServerAI = !!DEFAULT_AI_API_KEY;
  const hasUserAI = !!settings.ai_api_key;
  
  res.json({
    settings: {
      default_group_id: settings.default_group_id,
      ai_provider: settings.ai_provider || 'openai',
      ai_model: settings.ai_model || '',
      ai_base_url: settings.ai_base_url || '',
      has_ai_key: hasUserAI
    },
    ai_enabled: !!(aiConfig.apiKey),
    has_server_ai: hasServerAI,
    available_providers: [
      { id: 'openai', name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'] },
      { id: 'groq', name: 'Groq', models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'] },
      { id: 'anthropic', name: 'Anthropic', models: ['claude-3-5-sonnet-latest', 'claude-3-haiku-20240307'] },
      { id: 'azure', name: 'Azure OpenAI', models: ['gpt-4o', 'gpt-4'] },
      { id: 'custom', name: 'Custom (OpenAI Compatible)', models: [] }
    ]
  });
});

app.put('/api/settings', auth, (req, res) => {
  const { default_group_id, ai_provider, ai_model, ai_api_key, ai_base_url } = req.body;
  
  // Verify group belongs to user if provided
  if (default_group_id) {
    const group = db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(default_group_id, req.user.id);
    if (!group) return res.status(400).json({ error: 'Invalid group' });
  }
  
  // Ensure settings row exists
  const existing = db.prepare('SELECT user_id FROM user_settings WHERE user_id = ?').get(req.user.id);
  if (!existing) {
    db.prepare('INSERT INTO user_settings (user_id) VALUES (?)').run(req.user.id);
  }
  
  // Update settings
  db.prepare(`
    UPDATE user_settings SET 
      default_group_id = ?,
      ai_provider = ?,
      ai_model = ?,
      ai_api_key = CASE WHEN ? = '' THEN ai_api_key WHEN ? IS NULL THEN ai_api_key ELSE ? END,
      ai_base_url = ?
    WHERE user_id = ?
  `).run(
    default_group_id || null,
    ai_provider || 'openai',
    ai_model || null,
    ai_api_key, ai_api_key, ai_api_key,
    ai_base_url || null,
    req.user.id
  );
  
  // Clear AI key if explicitly requested
  if (ai_api_key === null) {
    db.prepare('UPDATE user_settings SET ai_api_key = NULL WHERE user_id = ?').run(req.user.id);
  }
  
  res.json({ success: true });
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
  
  // Get default group
  const settings = db.prepare('SELECT default_group_id FROM user_settings WHERE user_id = ?').get(req.user.id);
  
  res.json({ groups: groupsWithCount, ungroupedCount: ungroupedCount.count, defaultGroupId: settings?.default_group_id });
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
  
  // Clear default group if it's being deleted
  db.prepare('UPDATE user_settings SET default_group_id = NULL WHERE user_id = ? AND default_group_id = ?')
    .run(req.user.id, req.params.id);
  
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
  const aiConfig = getUserAIConfig(req.user.id);
  
  if (!aiConfig.apiKey) {
    return res.status(503).json({ error: 'AI not configured. Add your API key in Settings.' });
  }
  
  const { text, action } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  
  const prompts = {
    improve: 'Improve this text. Make it clearer, more professional, and fix any errors. Keep the same meaning and language. Return ONLY the improved text, nothing else.',
    fix: 'Fix any spelling, grammar, and punctuation errors in this text. Keep the same meaning and language. Return ONLY the corrected text, nothing else.',
    shorten: 'Make this text shorter and more concise while keeping the key information. Return ONLY the shortened text, nothing else.',
    expand: 'Expand this text with more detail, examples, and context while keeping the same tone and style. Make it more comprehensive. Return ONLY the expanded text, nothing else.',
    rewrite: 'Completely rewrite this text in a fresh way while keeping the same core meaning. Use different words, sentence structures, and phrasing. Return ONLY the rewritten text, nothing else.',
    professional: 'Rewrite this text in a professional business tone. Return ONLY the rewritten text, nothing else.',
    casual: 'Rewrite this text in a friendly, casual tone. Return ONLY the rewritten text, nothing else.',
    simplify: 'Simplify this text so it\'s easy to understand. Use simple words and short sentences. Return ONLY the simplified text, nothing else.',
    summarize: 'Summarize the key points of this text in a brief, clear manner. Return ONLY the summary, nothing else.',
    bullets: 'Convert this text into a well-organized bullet point list. Return ONLY the bullet points, nothing else.',
  };
  
  const systemPrompt = prompts[action] || prompts.improve;
  
  try {
    // Build URL and headers based on provider
    let url, headers;
    const provider = aiConfig.provider;
    
    if (provider === 'azure') {
      if (aiConfig.baseUrl.includes('/chat/completions')) {
        url = aiConfig.baseUrl;
      } else if (aiConfig.baseUrl.includes('/deployments/')) {
        url = `${aiConfig.baseUrl}/chat/completions?api-version=2025-01-01-preview`;
      } else {
        url = `${aiConfig.baseUrl}/openai/deployments/${aiConfig.model}/chat/completions?api-version=2025-01-01-preview`;
      }
      headers = {
        'api-key': aiConfig.apiKey,
        'Content-Type': 'application/json',
      };
    } else if (provider === 'anthropic') {
      url = 'https://api.anthropic.com/v1/messages';
      headers = {
        'x-api-key': aiConfig.apiKey,
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01'
      };
    } else {
      // OpenAI/Groq/Custom compatible format
      let baseUrl = aiConfig.baseUrl;
      if (provider === 'groq') baseUrl = 'https://api.groq.com/openai/v1';
      else if (provider === 'openai') baseUrl = 'https://api.openai.com/v1';
      url = `${baseUrl}/chat/completions`;
      headers = {
        'Authorization': `Bearer ${aiConfig.apiKey}`,
        'Content-Type': 'application/json',
      };
    }
    
    let body, parseResponse;
    
    if (provider === 'anthropic') {
      body = JSON.stringify({
        model: aiConfig.model || 'claude-3-5-sonnet-latest',
        max_tokens: 2000,
        system: systemPrompt,
        messages: [{ role: 'user', content: text }],
      });
      parseResponse = (data) => data.content?.[0]?.text?.trim();
    } else {
      body = JSON.stringify({
        model: aiConfig.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: text }
        ],
        max_tokens: 2000,
        temperature: 0.7,
      });
      parseResponse = (data) => data.choices?.[0]?.message?.content?.trim();
    }
    
    const response = await fetch(url, { method: 'POST', headers, body });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      console.error('AI error:', err);
      return res.status(500).json({ error: err.error?.message || 'AI request failed' });
    }
    
    const data = await response.json();
    const result = parseResponse(data);
    
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
  const aiConfig = getUserAIConfig(req.user.id);
  res.json({ enabled: !!aiConfig.apiKey });
});

// Serve app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`QuickNotes running on port ${PORT}`);
});
