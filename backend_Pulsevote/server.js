//Entry Point, connects to MongoDB

const mongoose = require('mongoose'); // this will be used later
const app = require('./app');
require('dotenv').config();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});