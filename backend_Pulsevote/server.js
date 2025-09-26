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