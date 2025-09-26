const mongoose = require('mongoose');
const app = require('./app');
const https = require('https');
const fs = require('fs');
require('dotenv').config();

const PORT = process.env.PORT || 5000;

const options = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem'),
};

https.createServer(options, app).listen(PORT, () => {
  console.log('Server running at https://localhost:' + PORT);
});

mongoose.connect(process.env.MONGO_URI)
.then(() => {
    https.createServer(options, app).listen(PORT, () => {
    console.log('Server running at https://localhost:' + PORT);
    });
})
.catch((err) => {
    console.error('MongoDB connection error:', err);
});


const mongoose = require('mongoose');
const app = require('./app');
const https = require('https');
const http = require('http');
const fs = require('fs');
require('dotenv').config();

const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0';
const useHttps = String(process.env.USE_HTTPS || '').toLowerCase() === 'true';
const mongo = process.env.MONGO_URI;

if (!mongo) {
console.error('Missing MONGO_URI');
process.exit(1);
}

mongoose.connect(mongo)
.then(() => {
    if (useHttps) {
    const keyPath = process.env.SSL_KEY_PATH || 'ssl/key.pem';
    const certPath = process.env.SSL_CERT_PATH || 'ssl/cert.pem';
    const haveFiles = fs.existsSync(keyPath) && fs.existsSync(certPath);

    if (!haveFiles) {
        console.warn('SSL files not found, falling back to HTTP');
    } else {
        const options = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
        https.createServer(options, app).listen(PORT, HOST, () => {
        console.log(`HTTPS server running at https://localhost:${PORT}`);
        });
        return;
    }
    }

    http.createServer(app).listen(PORT, HOST, () => {
    console.log(`HTTP server running at http://localhost:${PORT}`);
    });
})
.catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});