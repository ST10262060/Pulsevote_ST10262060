//Express set up 
const express = require('express');
const cors = require('cors'); // this will be discussed later
const helmet = require('helmet'); // this will be discussed later
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
res.send('PulseVote API running!');
});

module.exports = app;

const authRoutes = require("./routes/authRoutes");

app.use("/api/auth", authRoutes);

const cors = require('cors');
app.use(cors({
  origin: "https://localhost:5173",
  credentials: true
}));


const { protect } = require("./middleware/authMiddleware");

app.get("/api/protected", protect, (req, res) => {
  res.json({
    message: `Welcome, user ${req.user.id}! You have accessed protected data.`,
    timestamp: new Date()
  });
});


const jwt = require("jsonwebtoken");

const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer "))
    return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: "Token invalid or expired" });
  }
};

module.exports = { protect };