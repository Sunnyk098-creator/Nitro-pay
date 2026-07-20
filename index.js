const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const backendApp = require('./api/backend');

const app = express();

// Security Headers & Rate Limiting
app.use(helmet({ contentSecurityPolicy: false }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: { success: false, error: "Too many requests, please try again later." }
});
app.use(limiter);

// Direct Access Protection
app.use('/api', (req, res, next) => {
    if (req.method === 'GET' && req.headers.accept && req.headers.accept.includes('text/html')) {
        return res.redirect('/');
    }
    next();
});

// Mount Vercel-compatible backend module
app.use(backendApp);

// Serve Static Frontend (index.html)
app.use(express.static(__dirname));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
