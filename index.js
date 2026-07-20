require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const backendApp = require('./api/backend');

const server = express();
server.use(cors());

// Attach the backend Express app
server.use(backendApp);

// Serve the static frontend file
server.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start Server locally
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
