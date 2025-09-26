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

app.use(
helmet.contentSecurityPolicy({
    directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://apis.google.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'", "http://localhost:5000"], // or whichever port you use
    },
})
);

const organisationRoutes = require("./routes/organisationRoutes");

app.use("/api/organisations", organisationRoutes);

const pollRoutes = require("./routes/pollRoutes");

app.use("/api/polls", pollRoutes);


const express = require('express');
const app = express();

app.set('trust proxy', 1);

app.use(express.json());

app.get('/health', (req, res) => 
res.status(200).json({
    ok: true,
    ts: Date.now()
}));

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const authRoutes = require("./routes/authRoutes");
const organisationRoutes = require("./routes/organisationRoutes");
const pollRoutes = require("./routes/pollRoutes");
const { protect } = require("./middleware/authMiddleware");

dotenv.config();
const app = express();

app.use(helmet());

const CSP_CONNECT = (process.env.CSP_CONNECT || '').split(',').filter(Boolean);
const defaultConnect = [
"'self'",
"http://localhost:5000", "https://localhost:5000",
"http://localhost:5173", "https://localhost:5173",
"ws://localhost:5173", "wss://localhost:5173"
];

app.use(
helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://apis.google.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    imgSrc: ["'self'", "data:"],
    connectSrc: CSP_CONNECT.length ? CSP_CONNECT : defaultConnect,
    },
})
);

const allowed = (process.env.CORS_ORIGINS || "http://localhost:5173,https://localhost:5173")
.split(',')
.map(s => s.trim());

app.use(cors({
origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
},
credentials: true
}));

app.use(express.json());
app.set('trust proxy', 1);

app.use("/api/auth", authRoutes);
app.use("/api/organisations", organisationRoutes);
app.use("/api/polls", pollRoutes);

app.get('/health', (req, res) => 
res.status(200).json({
    ok: true,
    ts: Date.now()
}));

app.get('/', (req, res) => 
res.send('PulseVote API running!'));

app.get('/test', (req, res) => {
res.json({
    message: 'This is a test endpoint from PulseVote API!',
    status: 'success',
    timestamp: new Date()
});
});

app.get("/api/protected", protect, (req, res) => {
res.json({
    message: `Welcome, user ${req.user.id}! You have accessed protected data.`,
    timestamp: new Date()
});
});

module.exports = app;