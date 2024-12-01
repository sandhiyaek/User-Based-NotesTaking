const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
const port = 3000;
const SECRET_KEY = "SECRET"; // Replace with an environment variable in production

// Middleware
app.use(bodyParser.json());
app.use(cors());

// SQLite Database
const db = new sqlite3.Database("./notes_app.db", (err) => {
  if (err) console.error("Error opening database:", err);
  else console.log("Connected to SQLite database.");
});

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Register
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: "Error hashing password" });

    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
      if (err) {
        if (err.code === "SQLITE_CONSTRAINT") return res.status(400).json({ error: "Username already exists" });
        return res.status(500).json({ error: "Database error" });
      }
      res.status(201).json({ message: "User registered successfully" });
    });
  });
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(404).json({ error: "User not found" });

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ error: "Error comparing passwords" });
      if (!result) return res.status(401).json({ error: "Invalid credentials" });

      const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
      res.status(200).json({ token });
    });
  });
});

// Middleware to verify token
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Missing token" });
  jwt.verify(token.split(' ')[1], SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.userId = decoded.userId;
    next();
  });
};

// Add Note
app.post("/notes", authenticate, (req, res) => {
  const { title, content } = req.body;

  db.run(
    "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
    [req.userId, title, content],
    function (err) {
      if (err) return res.status(500).json({ error: "Database error" });
      res.status(201).json({ message: "Note added successfully", noteId: this.lastID });
    }
  );
});

// Get Notes
app.get("/notes", authenticate, (req, res) => {
  db.all("SELECT * FROM notes WHERE user_id = ?", [req.userId], (err, notes) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.status(200).json({ notes });
  });
});

// Update Note
app.put("/notes/:id", authenticate, (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  db.run(
    "UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?",
    [title, content, id, req.userId],
    function (err) {
      if (err) return res.status(500).json({ error: "Database error" });
      if (this.changes === 0) return res.status(404).json({ error: "Note not found" });
      res.status(200).json({ message: "Note updated successfully" });
    }
  );
});

// Delete Note
app.delete("/notes/:id", authenticate, (req, res) => {
  const { id } = req.params;

  db.run("DELETE FROM notes WHERE id = ? AND user_id = ?", [id, req.userId], function (err) {
    if (err) return res.status(500).json({ error: "Database error" });
    if (this.changes === 0) return res.status(404).json({ error: "Note not found" });
    res.status(200).json({ message: "Note deleted successfully" });
  });
});

app.get("/", (req, res) => {
  res.send("API is running");
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
