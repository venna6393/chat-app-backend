const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const cors = require("cors");
const https = require("https");

const app = express();
app.use(express.json());
app.use(cors());
const server = https.createServer(
  {
    key: fs.readFileSync("./key.pem"),
    cert: fs.readFileSync("./cert.pem"),
    passphrase: "9701386393",
  },
  app
);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["my-custom-header"],
    credentials: true,
  },
});
const PORT = process.env.PORT || 5000;

// MySQL connection
const connection = mysql.createConnection({
  host: "database-2.cr2qqs4icoyx.eu-north-1.rds.amazonaws.com",
  user: "root",
  password: "9701386393",
  database: "chat_app",
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to database: " + err.stack);
    return;
  }
  console.log("Connected to database as ID: " + connection.threadId);
});

// Routes

// User registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  connection.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    (error, results) => {
      if (error && error.code === "ER_DUP_ENTRY") {
        res.status(400).json({ error: "Username already exists" });
        return;
      }
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Error registering user" });
        return;
      }
      res.status(201).json({ message: "User registered successfully" });
    }
  );
});

// User login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Error logging in" });
        return;
      }

      if (results.length === 0) {
        res.status(401).json({ error: "Invalid username or password" });
        return;
      }

      const user = results[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        res.status(401).json({ error: "Invalid username or password" });
        return;
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username },
        "your-secret-key"
      );
      res.json({ token, userId: user.id });
    }
  );
});

// Send message
app.post("/messages", authenticateToken, (req, res) => {
  const { message } = req.body;
  const userId = req.user.userId;
  const userNameIs = req.user.username;

  connection.query(
    "INSERT INTO messages (user_id, message,user_name_is) VALUES (?, ?,?)",
    [userId, message, userNameIs],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: "Error sending message" });
        return;
      }
      io.emit("message", { userId, message }); // Broadcast message to all connected clients
      res
        .status(201)
        .json({ message: `Message sent successfully by ${userNameIs}` });
    }
  );
});

// Retrieve chat history
app.all("/messages", authenticateToken, (req, res) => {
  connection.query("SELECT * FROM messages", (error, messages) => {
    if (error) {
      console.error(error);
      res.status(500).json({ error: "Error retrieving chat history" });
      return;
    }
    return res.status(200).json({ messages });
  });
});

// WebSocket connection
io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });
  socket.on("send-message", (data) => {
    // Store message in database
    const { userId1, user1, message } = data;
    connection.query(
      "INSERT INTO messages (user_id,user_name_is, message) VALUES (?, ?,?)",
      [userId1, user1, message],
      (error, results) => {
        if (error) {
          console.error("Error storing message:", error);
          return;
        }
        console.log("Message stored in database:", userId1);
      }
    );

    // Broadcast the message to all connected clients
    io.emit("message", data);
  });
});

// Middleware function to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
