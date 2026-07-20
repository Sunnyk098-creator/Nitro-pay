const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const backendRoutes = require('./api/backend');

const app = express();

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Adjusted for local dev/Vercel standard HTML serving
}));
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Rate Limiting (Prevent Brute Force & DDoS)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, error: "Too many requests, please try again later." }
});
app.use(limiter);

// Direct Access Protection for APIs
app.use('/api', (req, res, next) => {
    // If request comes directly from browser URL bar (expects HTML)
    if (req.method === 'GET' && req.headers.accept && req.headers.accept.includes('text/html')) {
        return res.redirect('/');
    }
    next();
}, backendRoutes);

// Serve static frontend
app.use(express.static(__dirname));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
