const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'users.db');
const csvPath = path.join(dataDir, 'participant-credentials.csv');

// Remove existing db
if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);

const db = new sqlite3.Database(dbPath);

function toID(text) {
  if (typeof text !== 'string') return '';
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function generatePassword() {
  return crypto.randomBytes(20).toString('base64url');
}

db.serialize(() => {
  db.run(`CREATE TABLE users (
    userid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
  )`);

  const stmt = db.prepare("INSERT INTO users VALUES (?, ?, ?)");

  let csvContent = "username,password\n";

  const insertUser = (username, password) => {
    const hash = bcrypt.hashSync(password, 10);
    stmt.run(toID(username), username, hash);
    csvContent += `${username},${password}\n`;
  };

  // user for the rl bot (takes pwd from .env)
  insertUser('Bot', process.env.BOT_PASSWORD);

  // 250 Participants
  for (let i = 1; i <= 250; i++) {
    const id = String(i).padStart(3, '0');
    const username = `p${id}`;
    const password = generatePassword();
    insertUser(username, password);
  }

  stmt.finalize();

  fs.writeFileSync(csvPath, csvContent);
  console.log(`Generated users database at ${dbPath}`);
  console.log(`Generated credentials CSV at ${csvPath}`);
});

db.close();
