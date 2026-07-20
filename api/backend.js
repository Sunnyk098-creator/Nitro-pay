const express = require('express');
const firebase = require('firebase/compat/app');
require('firebase/compat/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = express.Router();

const firebaseConfig = {
  apiKey: "AIzaSyCo0XK4yHcpXncm9cmkJymL_3rffivHFok",
  authDomain: "nitro-pay-b9f4b.firebaseapp.com",
  databaseURL: "https://nitro-pay-b9f4b-default-rtdb.firebaseio.com",
  projectId: "nitro-pay-b9f4b",
  storageBucket: "nitro-pay-b9f4b.firebasestorage.app",
  messagingSenderId: "32865559465",
  appId: "1:32865559465:web:608cb539232769b603dab8"
};

// Initialize Firebase using the provided configuration
if (!firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
}

const db = firebase.database();

const JWT_SECRET = process.env.JWT_SECRET || 'nitro_wallet_jwt_super_secret_key';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'nitro_admin_secret_123';
const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Unauthorized access' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ success: false, error: 'Invalid or expired token' });
        req.user = decoded;
        next();
    });
};

const generateWalletNumber = () => Math.floor(1000000000 + Math.random() * 9000000000).toString();
const generatePaymentKey = () => Math.random().toString(36).substring(2, 12).toUpperCase();

router.post('/signup', async (req, res) => {
    try {
        const { name, email, phone, telegramId, password, pin } = req.body;
        if (!name || !email || !phone || !telegramId || !password || !pin) {
            return res.status(400).json({ success: false, error: 'Missing required fields' });
        }

        const usersRef = db.ref('users');
        const snapshot = await usersRef.once('value');
        const users = snapshot.val() || {};
        
        for (const uid in users) {
            if (users[uid].email === email) return res.status(400).json({ success: false, error: 'Email already exists' });
            if (users[uid].phone === phone) return res.status(400).json({ success: false, error: 'Phone number already exists' });
            if (users[uid].telegramId === telegramId) return res.status(400).json({ success: false, error: 'Telegram ID already exists' });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const pinHash = await bcrypt.hash(pin, SALT_ROUNDS);
        const walletNumber = generateWalletNumber();
        const paymentKey = generatePaymentKey();
        const uid = db.ref().push().key;

        await db.ref(`users/${uid}`).set({
            uid, name, email, phone, telegramId, passwordHash, pinHash,
            walletNumber, paymentKey, balance: 0, createdAt: Date.now(), transactions: {}
        });

        res.json({ success: true, message: 'Signup successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const snapshot = await db.ref('users').once('value');
        const users = snapshot.val() || {};
        
        let foundUser = null;
        for (const uid in users) {
            if (users[uid].email === identifier || users[uid].phone === identifier) {
                foundUser = users[uid];
                break;
            }
        }

        if (!foundUser) return res.status(401).json({ success: false, error: 'Invalid credentials' });
        
        const match = await bcrypt.compare(password, foundUser.passwordHash);
        if (!match) return res.status(401).json({ success: false, error: 'Invalid credentials' });

        const token = jwt.sign({ uid: foundUser.uid, walletNumber: foundUser.walletNumber }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ 
            success: true, 
            token, 
            user: { 
                name: foundUser.name, 
                walletNumber: foundUser.walletNumber, 
                balance: foundUser.balance, 
                paymentKey: foundUser.paymentKey 
            } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

router.get('/history', verifyToken, async (req, res) => {
    try {
        const snapshot = await db.ref(`users/${req.user.uid}/transactions`).once('value');
        res.json({ success: true, transactions: snapshot.val() || {} });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

router.post('/send', verifyToken, async (req, res) => {
    try {
        const { receiverWallet, amount, pin, comment } = req.body;
        const amt = parseFloat(amount);
        
        if (!receiverWallet || isNaN(amt) || amt <= 0 || !pin) {
            return res.status(400).json({ success: false, error: 'Invalid input parameters' });
        }
        
        if (receiverWallet === req.user.walletNumber) {
            return res.status(400).json({ success: false, error: 'Cannot send money to yourself' });
        }

        const snapshot = await db.ref('users').once('value');
        const users = snapshot.val() || {};
        
        const sender = users[req.user.uid];
        let receiverId = null;
        
        for (const uid in users) {
            if (users[uid].walletNumber === receiverWallet) {
                receiverId = uid;
                break;
            }
        }

        if (!receiverId) return res.status(404).json({ success: false, error: 'Receiver wallet not found' });
        if (sender.balance < amt) return res.status(400).json({ success: false, error: 'Insufficient balance' });

        const pinMatch = await bcrypt.compare(pin, sender.pinHash);
        if (!pinMatch) return res.status(401).json({ success: false, error: 'Invalid PIN' });

        const txId = db.ref().push().key;
        const time = Date.now();

        await db.ref(`users/${req.user.uid}`).update({ balance: sender.balance - amt });
        await db.ref(`users/${req.user.uid}/transactions/${txId}`).set({ 
            type: 'debit', amount: amt, comment: comment || '', receiverWallet, time, status: 'success' 
        });

        await db.ref(`users/${receiverId}`).update({ balance: users[receiverId].balance + amt });
        await db.ref(`users/${receiverId}/transactions/${txId}`).set({ 
            type: 'credit', amount: amt, comment: comment || '', senderWallet: req.user.walletNumber, time, status: 'success' 
        });

        res.json({ success: true, message: 'Transfer successful' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

router.post('/paymentkey', verifyToken, async (req, res) => {
    try {
        const newKey = generatePaymentKey();
        await db.ref(`users/${req.user.uid}`).update({ paymentKey: newKey });
        res.json({ success: true, paymentKey: newKey });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

router.get('/addfund', async (req, res) => {
    try {
        const { wallet, amount, key } = req.query;
        if (!wallet || !amount || !key) return res.status(400).json({ success: false, error: 'Missing parameters' });
        
        if (key !== ADMIN_SECRET) return res.status(401).json({ success: false, error: 'Unauthorized access' });
        
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ success: false, error: 'Invalid amount' });

        const snapshot = await db.ref('users').once('value');
        const users = snapshot.val() || {};
        
        let targetUid = null;
        for (const uid in users) {
            if (users[uid].walletNumber === wallet) {
                targetUid = uid;
                break;
            }
        }

        if (!targetUid) return res.status(404).json({ success: false, error: 'Invalid wallet number' });

        const txId = db.ref().push().key;
        const time = Date.now();

        await db.ref(`users/${targetUid}`).update({ balance: users[targetUid].balance + amt });
        await db.ref(`users/${targetUid}/transactions/${txId}`).set({ 
            type: 'credit', amount: amt, comment: 'Fund Added via Bot', time, status: 'success' 
        });

        res.json({ success: true, message: 'Fund added successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

module.exports = router;
