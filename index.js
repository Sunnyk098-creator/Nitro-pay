require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');

const backendRoutes = require('./api/backend');

const app = express();

// Security middlewares
app.use(helmet({ 
    contentSecurityPolicy: false // Disabled temporarily to allow external fonts/icons
}));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// Browser Protection Middleware
app.use('/api', (req, res, next) => {
    const acceptHeader = req.headers.accept || '';
    if (req.method === 'GET' && acceptHeader.includes('text/html')) {
        return res.redirect('/');
    }
    next();
});

// Connect API routes
app.use('/api', backendRoutes);

// Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Fallback redirect for undefined routes
app.use((req, res) => {
    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
