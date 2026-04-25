const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const dbPath = path.join(__dirname, '..', 'data', 'users.db');
const privateKeyPath = path.join(__dirname, '..', 'data', 'keys', 'private.pem');

let db;
let privateKey;

try {
  privateKey = fs.readFileSync(privateKeyPath, 'utf8');
} catch (err) {
  console.error("Could not read private key. Did you run generate-keys.js?");
}

if (fs.existsSync(dbPath)) {
  db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
      console.error(err.message);
    }
  });
} else {
  console.error("Users database not found. Did you run generate-users.js?");
}

function toID(text) {
  if (typeof text !== 'string') return '';
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '');
}


app.all(['/api/action.php', '/action.php', '/api/', '/'], (req, res) => {
  const params = { ...req.query, ...req.body };
  let { act, name, pass, newpass, newname } = params;
  let challenge = params.challenge || params.challstr;
  if (challenge) {
    challenge = decodeURIComponent(challenge);
    if (challenge.includes('|')) challenge = challenge.split('|')[1];
  }

  // Case-insensitive action check
  act = (act || '').toLowerCase();

  if (act === 'login') {
    const userid = toID(name);

    if (!db) {
      console.log(`Login attempt failed: database not loaded`);
      return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Database not loaded' }));
    }

    if (!userid) {
       console.log(`Login attempt failed: no username provided`);
       return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'No username provided' }));
    }

    db.get('SELECT * FROM users WHERE userid = ?', [userid], (err, row) => {
      if (err) {
        console.error(`DB Error: ${err.message}`);
        return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Internal database error' }));
      }
      if (!row) {
        console.log(`Failed login: ${userid} (user not found)`);
        return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'User not found' }));
      }

      const match = bcrypt.compareSync(pass || '', row.password_hash);
      if (!match) {
        console.log(`Failed login: ${userid} (invalid password)`);
        return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Invalid password' }));
      }

      const timestamp = Math.floor(Date.now() / 1000);
      const hostname = ''; // Empty hostname is safer
      const tokenData = `${challenge},${userid},2,${timestamp},${hostname}`;

      const signer = crypto.createSign('RSA-SHA1');
      signer.update(tokenData);
      const sig = signer.sign(privateKey, 'hex');

      console.log(`Successful login: ${userid} (${row.username})`);
      return res.send(']' + JSON.stringify({
        actionsuccess: true,
        curuser: {
          loggedin: true,
          userid: userid,
          username: row.username
        },
        assertion: `${tokenData};${sig}`
      }));
    });
  } else if (act === 'changepassword') {
    const userid = toID(name);
    if (!userid || !pass || !newpass) {
      return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Missing fields' }));
    }

    db.get('SELECT * FROM users WHERE userid = ?', [userid], (err, row) => {
      if (err || !row) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'User not found' }));
      
      const match = bcrypt.compareSync(pass, row.password_hash);
      if (!match) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Invalid current password' }));

      const newHash = bcrypt.hashSync(newpass, 10);
      db.run('UPDATE users SET password_hash = ? WHERE userid = ?', [newHash, userid], (err) => {
        if (err) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Database error' }));
        console.log(`Password changed for user: ${userid}`);
        return res.send(']' + JSON.stringify({ actionsuccess: true }));
      });
    });
  } else if (act === 'changeusername') {
    const userid = toID(name);
    const newuserid = toID(newname);
    if (!userid || !pass || !newname || !newuserid) {
      return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Missing fields' }));
    }

    if (userid === newuserid) {
       // Just update the display name if the ID is the same (e.g. changing capitalization)
       db.get('SELECT * FROM users WHERE userid = ?', [userid], (err, row) => {
         if (err || !row) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'User not found' }));
         const match = bcrypt.compareSync(pass, row.password_hash);
         if (!match) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Invalid password' }));
         
         db.run('UPDATE users SET username = ? WHERE userid = ?', [newname, userid], (err) => {
           if (err) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Database error' }));
           console.log(`Username (display) changed for user: ${userid} to ${newname}`);
           return res.send(']' + JSON.stringify({ actionsuccess: true, newuserid: userid, newusername: newname }));
         });
       });
       return;
    }

    db.get('SELECT * FROM users WHERE userid = ?', [newuserid], (err, row) => {
      if (row) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'New username already taken' }));
      
      db.get('SELECT * FROM users WHERE userid = ?', [userid], (err, row) => {
        if (err || !row) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'User not found' }));
        
        const match = bcrypt.compareSync(pass, row.password_hash);
        if (!match) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Invalid password' }));

        db.run('UPDATE users SET userid = ?, username = ? WHERE userid = ?', [newuserid, newname, userid], (err) => {
          if (err) return res.send(']' + JSON.stringify({ actionsuccess: false, actionerror: 'Database error' }));
          console.log(`Username changed: ${userid} -> ${newuserid} (${newname})`);
          return res.send(']' + JSON.stringify({ actionsuccess: true, newuserid: newuserid, newusername: newname }));
        });
      });
    });
  } else if (act === 'upkeep' || act === 'getassertion' || act === 'getteams' || act === 'saveteams') {
    if (act === 'getteams') return res.send(']' + JSON.stringify([]));
    return res.send(']' + JSON.stringify({ actionsuccess: true }));
  } else if (req.path === '/' || req.path === '/api/') {
    res.send('Login server is up');
  } else {
    if (act) console.log(`Unknown action: ${act}`);
    res.send(']');
  }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Login server listening on port ${PORT}`);
});
