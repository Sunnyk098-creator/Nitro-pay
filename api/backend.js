const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { initializeApp } = require('firebase/app');
const { getDatabase, ref, set, get, update, push, child } = require('firebase/database');

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Connect to Firebase using Vercel Environment Variables
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  databaseURL: process.env.FIREBASE_DATABASE_URL,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getDatabase(firebaseApp);
const JWT_SECRET = process.env.JWT_SECRET || "nitro-pay-ultra-secure-jwt-secret";

const generateId = (length) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
};

app.all('/api/backend', async (req, res) => {
    const action = req.query.action;

    const authenticate = (callback) => {
        const token = req.headers['authorization']?.split(' ')[1] || req.cookies?.token;
        if (!token) return res.status(401).json({ success: false, error: "Unauthorized access" });

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ success: false, error: "Session expired, please login again" });
            req.user = user;
            callback();
        });
    };

    try {
        // ---------------------------------------------------------
        // 1. SIGN UP (Fix: No Bonus, Phone Number = Wallet)
        // ---------------------------------------------------------
        if (action === 'signup' && req.method === 'POST') {
            const { fullName, email, phone, telegramId, password, pin } = req.body;
            
            if (!fullName || !email || !phone || !telegramId || !password || !pin) {
                return res.status(400).json({ success: false, error: "All fields are required" });
            }
            if (password.length < 8) return res.status(400).json({ success: false, error: "Password must be at least 8 chars" });
            if (!/^\d{4}$/.test(pin)) return res.status(400).json({ success: false, error: "PIN must be exactly 4 digits" });

            const usersRef = ref(db, 'users');
            const snapshot = await get(usersRef);
            if (snapshot.exists()) {
                let exists = false;
                snapshot.forEach((c) => {
                    const u = c.val();
                    if (u.email === email || u.phone === phone || u.telegramId === telegramId) exists = true;
                });
                if (exists) return res.status(400).json({ success: false, error: "Email, Phone, or Telegram ID is already registered" });
            }

            const uid = push(child(ref(db), 'users')).key;
            const passwordHash = await bcrypt.hash(password, 12);
            const pinHash = await bcrypt.hash(pin, 12);
            
            // WALLET NUMBER = PHONE NUMBER
            const walletNumber = phone; 
            const paymentKey = generateId(10);

            // NO SIGNUP BONUS TRANSACTIONS HERE
            const newUser = {
                uid, name: fullName, email, phone, telegramId, walletNumber,
                balance: 0, // EXACTLY ZERO
                pinHash, passwordHash, paymentKey,
                createdAt: Date.now()
            };

            await set(ref(db, 'users/' + uid), newUser);
            return res.json({ success: true, message: "Account created successfully" });
        }

        // ---------------------------------------------------------
        // 2. LOGIN
        // ---------------------------------------------------------
        else if (action === 'login' && req.method === 'POST') {
            const { identifier, password } = req.body;
            const snapshot = await get(ref(db, 'users'));
            let foundUser = null;

            if (snapshot.exists()) {
                snapshot.forEach((c) => {
                    const u = c.val();
                    if (u.email === identifier || u.phone === identifier) foundUser = u;
                });
            }

            if (!foundUser) return res.status(401).json({ success: false, error: "Invalid credentials" });

            const isMatch = await bcrypt.compare(password, foundUser.passwordHash);
            if (!isMatch) return res.status(401).json({ success: false, error: "Invalid credentials" });

            const token = jwt.sign({ uid: foundUser.uid, walletNumber: foundUser.walletNumber }, JWT_SECRET, { expiresIn: '24h' });
            res.cookie('token', token, { httpOnly: true, secure: true });
            
            delete foundUser.passwordHash; delete foundUser.pinHash;
            return res.json({ success: true, token, user: foundUser });
        }

        // ---------------------------------------------------------
        // 3. GET USER DETAILS
        // ---------------------------------------------------------
        else if (action === 'me' && req.method === 'GET') {
            authenticate(async () => {
                const snapshot = await get(ref(db, `users/${req.user.uid}`));
                if (!snapshot.exists()) return res.status(404).json({ success: false, error: "User not found" });
                const user = snapshot.val();
                delete user.passwordHash; delete user.pinHash;
                res.json({ success: true, user });
            });
        }

        // ---------------------------------------------------------
        // 4. ADD FUND VIA BOT API (Uses Admin Password from Vercel)
        // ---------------------------------------------------------
        else if (action === 'addfund' && req.method === 'GET') {
            const { wallet, amount, key } = req.query;
            const parsedAmount = parseFloat(amount);

            if (!wallet || isNaN(parsedAmount) || parsedAmount <= 0 || !key) {
                return res.status(400).json({ success: false, error: "Invalid request parameters" });
            }

            const envAdminPassword = process.env.ADMIN_API_PASSWORD;

            if (!envAdminPassword || key !== envAdminPassword) {
                return res.status(401).json({ success: false, error: "Unauthorized: Invalid Admin API Password" });
            }

            const snapshot = await get(ref(db, 'users'));
            let targetUser = null; let targetUid = null;

            if (snapshot.exists()) {
                snapshot.forEach((c) => {
                    if (c.val().walletNumber === wallet || c.val().phone === wallet) { 
                        targetUser = c.val(); targetUid = c.key; 
                    }
                });
            }

            if (!targetUser) return res.status(404).json({ success: false, error: "User/Wallet not found" });

            const txId = generateId(12);
            const updates = {};
            updates[`users/${targetUid}/balance`] = (targetUser.balance || 0) + parsedAmount;
            updates[`users/${targetUid}/transactions/${txId}`] = { type: 'credit', amount: parsedAmount, comment: 'Fund Added by Admin', time: Date.now(), status: 'completed' };

            await update(ref(db), updates);
            return res.json({ success: true, message: "Fund added successfully" });
        }

        // ---------------------------------------------------------
        // 5. SEND MONEY
        // ---------------------------------------------------------
        else if (action === 'send' && req.method === 'POST') {
            authenticate(async () => {
                const { receiverWallet, amount, comment, pin } = req.body;
                const parsedAmount = parseFloat(amount);

                if (parsedAmount <= 0) return res.status(400).json({ success: false, error: "Invalid amount" });
                if (req.user.walletNumber === receiverWallet || req.user.phone === receiverWallet) {
                    return res.status(400).json({ success: false, error: "Cannot send to yourself" });
                }

                const senderSnap = await get(ref(db, `users/${req.user.uid}`));
                const sender = senderSnap.val();
                const pinMatch = await bcrypt.compare(pin, sender.pinHash);
                if (!pinMatch) return res.status(401).json({ success: false, error: "Invalid PIN" });
                if ((sender.balance || 0) < parsedAmount) return res.status(400).json({ success: false, error: "Insufficient balance" });

                const allUsersSnap = await get(ref(db, 'users'));
                let receiver = null; let receiverUid = null;
                allUsersSnap.forEach(c => {
                    if (c.val().walletNumber === receiverWallet || c.val().phone === receiverWallet) { receiver = c.val(); receiverUid = c.key; }
                });

                if (!receiver) return res.status(404).json({ success: false, error: "Receiver not found" });

                const txId = generateId(12);
                const time = Date.now();
                const updates = {};

                updates[`users/${req.user.uid}/balance`] = sender.balance - parsedAmount;
                updates[`users/${receiverUid}/balance`] = (receiver.balance || 0) + parsedAmount;
                
                updates[`users/${req.user.uid}/transactions/${txId}`] = { type: 'debit', amount: parsedAmount, comment: comment || 'Transfer', receiverWallet, time, status: 'completed' };
                updates[`users/${receiverUid}/transactions/${txId}`] = { type: 'credit', amount: parsedAmount, comment: comment || 'Received', senderWallet: sender.walletNumber, time, status: 'completed' };

                await update(ref(db), updates);
                res.json({ success: true, message: "Transfer successful" });
            });
        }

        // ---------------------------------------------------------
        // 6. REGENERATE KEY
        // ---------------------------------------------------------
        else if (action === 'regenerate' && req.method === 'POST') {
            authenticate(async () => {
                const newKey = generateId(10);
                await update(ref(db, `users/${req.user.uid}`), { paymentKey: newKey });
                res.json({ success: true, paymentKey: newKey });
            });
        } 
        
        else {
            res.status(404).json({ success: false, error: "API route not found" });
        }

    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

module.exports = app;
