const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'ntg_super_secret_key';

// --- Инициализация БД (файл db.json) ---
let db = { users: [], messages: [] };
if (fs.existsSync('./db.json')) {
  db = JSON.parse(fs.readFileSync('./db.json'));
}
const saveDb = () => fs.writeFileSync('./db.json', JSON.stringify(db, null, 2));

// --- HTTP Сервер (для регистрации/логина) ---
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    if (req.url === '/register' && req.method === 'POST') {
      const { username, password } = JSON.parse(body);
      if (db.users.find(u => u.username === username)) {
        res.writeHead(400); return res.end(JSON.stringify({ error: 'Пользователь уже существует' }));
      }
      const hashedPassword = bcrypt.hashSync(password, 10);
      db.users.push({ id: Date.now(), username, password: hashedPassword });
      saveDb();
      res.writeHead(200); return res.end(JSON.stringify({ success: true }));
    }

    if (req.url === '/login' && req.method === 'POST') {
      const { username, password } = JSON.parse(body);
      const user = db.users.find(u => u.username === username);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        res.writeHead(401); return res.end(JSON.stringify({ error: 'Неверный логин или пароль' }));
      }
      const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
      res.writeHead(200); return res.end(JSON.stringify({ token, username: user.username }));
    }
  });
});

// --- WebSocket Сервер (для сообщений) ---
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'history', data: db.messages }));

  ws.on('message', (message) => {
    const parsed = JSON.parse(message);
    if (parsed.type === 'new_message') {
      const msg = parsed.data;
      msg.time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      db.messages.push(msg);
      saveDb();
      
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'new_message', data: msg }));
        }
      });
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Сервер на порту ${PORT}`));