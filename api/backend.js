const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { initializeApp } = require('firebase/app');
const { getDatabase, ref, set, get, update, push, child } = require('firebase/database');

const router = express.Router();

// SANITIZED FIREBASE CONFIGURATION
const firebaseConfig = {
  apiKey: "AIzaSyCo0XK4yHcpXncm9cmkJymL_3rffivHFok",
  authDomain: "nitro-pay-b9f4b.firebaseapp.com",
  databaseURL: "https://nitro-pay-b9f4b-default-rtdb.firebaseio.com",
  projectId: "nitro-pay-b9f4b",
  storageBucket: "nitro-pay-b9f4b.firebasestorage.app",
  messagingSenderId: "32865559465",
  appId: "1:32865559465:web:608cb539232769b603dab8"
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getDatabase(firebaseApp);

const JWT_SECRET = process.env.JWT_SECRET || "ultra-secure-jwt-secret-key-change-in-prod";

// Middleware: Authenticate JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ success: false, error: "Unauthorized access" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: "Session expired or invalid" });
        req.user = user;
        next();
    });
};

// Generate Random Strings
const generateId = (length) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
};

// Routes
router.post('/signup', async (req, res) => {
    try {
        const { fullName, email, phone, telegramId, password, pin } = req.body;
        if (!fullName || !email || !phone || !telegramId || !password || !pin) {
            return res.status(400).json({ success: false, error: "All fields are required" });
        }
        if (password.length < 8) return res.status(400).json({ success: false, error: "Password must be at least 8 characters" });
        if (!/^\d{4}$/.test(pin)) return res.status(400).json({ success: false, error: "PIN must be exactly 4 digits" });

        // Check duplicates (Mock implementation - in prod, query all users or use unique indexing)
        const usersRef = ref(db, 'users');
        const snapshot = await get(usersRef);
        if (snapshot.exists()) {
            let exists = false;
            snapshot.forEach((childSnapshot) => {
                const u = childSnapshot.val();
                if (u.email === email || u.phone === phone || u.telegramId === telegramId) exists = true;
            });
            if (exists) return res.status(400).json({ success: false, error: "Email, Phone, or Telegram ID already registered" });
        }

        const uid = push(child(ref(db), 'users')).key;
        const passwordHash = await bcrypt.hash(password, 12);
        const pinHash = await bcrypt.hash(pin, 12);
        const walletNumber = 'W' + generateId(9);
        const paymentKey = generateId(10);

        const newUser = {
            uid, name: fullName, email, phone, telegramId, walletNumber,
            balance: 50, // Signup Bonus
            pinHash, passwordHash, paymentKey,
            createdAt: Date.now(),
            transactions: { init: { type: 'credit', amount: 50, comment: 'Signup Bonus', time: Date.now(), status: 'completed' } }
        };

        await set(ref(db, 'users/' + uid), newUser);
        res.json({ success: true, message: "Account created successfully" });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const snapshot = await get(ref(db, 'users'));
        let foundUser = null;

        if (snapshot.exists()) {
            snapshot.forEach((childSnapshot) => {
                const u = childSnapshot.val();
                if (u.email === identifier || u.phone === identifier) foundUser = u;
            });
        }

        if (!foundUser) return res.status(401).json({ success: false, error: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, foundUser.passwordHash);
        if (!isMatch) return res.status(401).json({ success: false, error: "Invalid credentials" });

        const token = jwt.sign({ uid: foundUser.uid, walletNumber: foundUser.walletNumber }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: true });
        
        // Strip sensitive data before sending
        delete foundUser.passwordHash;
        delete foundUser.pinHash;
        
        res.json({ success: true, token, user: foundUser });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Get Current User Data
router.get('/me', authenticateToken, async (req, res) => {
    try {
        const snapshot = await get(ref(db, `users/${req.user.uid}`));
        if (!snapshot.exists()) return res.status(404).json({ success: false, error: "User not found" });
        const user = snapshot.val();
        delete user.passwordHash; delete user.pinHash;
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

router.get('/addfund', async (req, res) => {
    // API format requested: /api/addfund?wallet={walletNumber}&amount={amount}&key={password}
    try {
        const { wallet, amount, key } = req.query;
        const parsedAmount = parseFloat(amount);

        if (!wallet || isNaN(parsedAmount) || parsedAmount <= 0 || !key) {
            return res.status(400).json({ success: false, error: "Invalid request parameters" });
        }

        const snapshot = await get(ref(db, 'users'));
        let targetUser = null;
        let targetUid = null;

        if (snapshot.exists()) {
            snapshot.forEach((childSnapshot) => {
                const u = childSnapshot.val();
                if (u.walletNumber === wallet) {
                    targetUser = u; targetUid = childSnapshot.key;
                }
            });
        }

        if (!targetUser) return res.status(404).json({ success: false, error: "Wallet not found" });

        const isMatch = await bcrypt.compare(key, targetUser.passwordHash);
        if (!isMatch) return res.status(401).json({ success: false, error: "Unauthorized access" });

        const newBalance = targetUser.balance + parsedAmount;
        const txId = generateId(12);
        
        const updates = {};
        updates[`users/${targetUid}/balance`] = newBalance;
        updates[`users/${targetUid}/transactions/${txId}`] = {
            type: 'credit', amount: parsedAmount, comment: 'API Fund Add', time: Date.now(), status: 'completed'
        };

        await update(ref(db), updates);
        res.json({ success: true, message: "Fund added successfully" });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

router.post('/send', authenticateToken, async (req, res) => {
    try {
        const { receiverWallet, amount, comment, pin } = req.body;
        const parsedAmount = parseFloat(amount);

        if (parsedAmount <= 0) return res.status(400).json({ success: false, error: "Invalid amount" });
        if (req.user.walletNumber === receiverWallet) return res.status(400).json({ success: false, error: "Cannot send to yourself" });

        // Verify PIN
        const senderSnap = await get(ref(db, `users/${req.user.uid}`));
        const sender = senderSnap.val();
        const pinMatch = await bcrypt.compare(pin, sender.pinHash);
        if (!pinMatch) return res.status(401).json({ success: false, error: "Invalid PIN" });

        if (sender.balance < parsedAmount) return res.status(400).json({ success: false, error: "Insufficient balance" });

        // Find receiver
        const allUsersSnap = await get(ref(db, 'users'));
        let receiver = null; let receiverUid = null;
        allUsersSnap.forEach(child => {
            if (child.val().walletNumber === receiverWallet) { receiver = child.val(); receiverUid = child.key; }
        });

        if (!receiver) return res.status(404).json({ success: false, error: "Receiver wallet not found" });

        const txId = generateId(12);
        const time = Date.now();

        const updates = {};
        updates[`users/${req.user.uid}/balance`] = sender.balance - parsedAmount;
        updates[`users/${receiverUid}/balance`] = receiver.balance + parsedAmount;
        
        updates[`users/${req.user.uid}/transactions/${txId}`] = { type: 'debit', amount: parsedAmount, comment: comment || 'Transfer', receiverWallet, time, status: 'completed' };
        updates[`users/${receiverUid}/transactions/${txId}`] = { type: 'credit', amount: parsedAmount, comment: comment || 'Received', senderWallet: sender.walletNumber, time, status: 'completed' };

        await update(ref(db), updates);
        res.json({ success: true, message: "Transfer successful" });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

router.post('/paymentkey/regenerate', authenticateToken, async (req, res) => {
    try {
        const newKey = generateId(10);
        await update(ref(db, `users/${req.user.uid}`), { paymentKey: newKey });
        res.json({ success: true, paymentKey: newKey });
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

module.exports = router;
