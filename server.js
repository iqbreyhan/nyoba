const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Konfigurasi CORS
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' ? 
        [process.env.FRONTEND_URL] : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};
app.use(cors(corsOptions));

// Middleware Keamanan
app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "http://localhost:3000"], // Added localhost for API calls
        }
    } : false
}));

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 100,
    message: { message: 'Too many requests, please try again later.', code: 'RATE_LIMIT_EXCEEDED' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 10,
    message: { message: 'Too many authentication attempts, please try again later.', code: 'AUTH_RATE_LIMIT' },
    standardHeaders: true,
    legacyHeaders: false
});

// Middleware Dasar
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Koneksi MongoDB dengan error handling yang lebih baik
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
        });
        
        console.log('✅ Connected to MongoDB');
        console.log(`📍 Database: ${conn.connection.name} on ${conn.connection.host}:${conn.connection.port}`);
        
        // Handle connection events
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
        });
        
        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️  MongoDB disconnected');
        });
        
        mongoose.connection.on('reconnected', () => {
            console.log('✅ MongoDB reconnected');
        });
        
    } catch (err) {
        console.error('❌ MongoDB connection failed:', err);
        process.exit(1);
    }
};

connectDB();

// Schema User dengan Daily Quests - diperbaiki validasi
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [20, 'Username cannot exceed 20 characters'],
        index: true,
        match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscore and dash']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email'],
        index: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    level: {
        type: Number,
        default: 1,
        min: [1, 'Level cannot be less than 1'],
        max: [999, 'Level cannot exceed 999'],
        index: true
    },
    exp: {
        type: Number,
        default: 0,
        min: [0, 'Experience cannot be negative']
    },
    expToNext: {
        type: Number,
        default: 100,
        min: [1, 'Experience to next level must be positive']
    },
    statPoints: {
        type: Number,
        default: 0,
        min: [0, 'Stat points cannot be negative']
    },
    stats: {
        str: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] },
        agi: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] },
        int: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] },
        stm: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] },
        vit: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] },
        per: { type: Number, default: 10, min: [0, 'Stat cannot be negative'], max: [999, 'Stat cannot exceed 999'] }
    },
    activities: [{
        name: { type: String, required: true, trim: true },
        duration: { type: Number, required: true, min: 1, max: 600 },
        intensity: { type: String, required: true, enum: ['low', 'medium', 'high'] },
        reps: { type: Number, default: 0, min: 0, max: 10000 },
        exp: { type: Number, required: true, min: 0 },
        date: { type: Date, default: Date.now }
    }],
    dailyQuests: [{
        id: { type: String, required: true },
        title: { type: String, required: true, trim: true },
        description: { type: String, trim: true },
        target: { type: Number, required: true, min: 1 },
        reward: { type: Number, required: true, min: 0 },
        type: { 
            type: String, 
            required: true,
            enum: ['duration', 'total_duration', 'reps', 'sessions']
        },
        activities: [{ type: String, trim: true }],
        progress: { type: Number, default: 0, min: 0 },
        completed: { type: Boolean, default: false },
        claimed: { type: Boolean, default: false }
    }],
    lastQuestReset: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    // Menambahkan field role
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
}, {
    strict: true,
    validateBeforeSave: true,
    timestamps: false // Karena kita sudah punya createdAt manual
});

// Indexes untuk performance
userSchema.index({ level: -1, exp: -1 }); // Compound index untuk leaderboard
userSchema.index({ username: 1, email: 1 }); // Compound index untuk login
userSchema.index({ lastLogin: -1 }); // Index untuk tracking active users

const User = mongoose.model('User', userSchema);

// Schema for Activity Types (for Admin Panel)
const activityTypeSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true },
    base_exp: { type: Number, required: true, min: 0 },
    category: { type: String, required: true, trim: true }
});
const ActivityType = mongoose.model('ActivityType', activityTypeSchema);

// Schema for Quests (for Admin Panel)
const questSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true, trim: true }, // Use string ID for quests
    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    target: { type: Number, required: true, min: 1 },
    reward: { type: Number, required: true, min: 0 },
    type: { 
        type: String, 
        required: true,
        enum: ['duration', 'total_duration', 'reps', 'sessions']
    },
    activities: [{ type: String, trim: true }], // Keywords for activity matching
});
const Quest = mongoose.model('Quest', questSchema);


// Default Daily Quests Template
const DEFAULT_DAILY_QUESTS = [
    {
        id: 'cardio_warrior',
        title: 'Cardio Warrior',
        description: 'Complete 30 minutes of cardio training',
        target: 30,
        reward: 150,
        type: 'duration',
        activities: ['running', 'cycling', 'cardio', 'neural cardio', 'combat cardio'],
        progress: 0,
        completed: false,
        claimed: false
    },
    {
        id: 'strength_master',
        title: 'Strength Master',
        description: 'Complete 45 minutes of strength training',
        target: 45,
        reward: 200,
        type: 'duration',
        activities: ['strength', 'weight', 'lifting', 'combat training', 'power training'],
        progress: 0,
        completed: false,
        claimed: false
    },
    {
        id: 'endurance_hunter',
        title: 'Endurance Hunter',
        description: 'Train for at least 60 minutes total',
        target: 60,
        reward: 250,
        type: 'total_duration',
        activities: [],
        progress: 0,
        completed: false,
        claimed: false
    },
    {
        id: 'rep_champion',
        title: 'Rep Champion',
        description: 'Complete 100 repetitions in any exercise',
        target: 100,
        reward: 180,
        type: 'reps',
        activities: [],
        progress: 0,
        completed: false,
        claimed: false
    },
    {
        id: 'consistency_king',
        title: 'Consistency King',
        description: 'Complete 3 different training sessions',
        target: 3,
        reward: 300,
        type: 'sessions',
        activities: [],
        progress: 0,
        completed: false,
        claimed: false
    }
];

// Function untuk membuat deep copy daily quests
async function createDailyQuestsForUser() {
    // Fetch active quests from the Quest model if available, otherwise use default
    const activeQuests = await Quest.find({});
    if (activeQuests.length > 0) {
        return activeQuests.map(quest => ({
            id: quest.id,
            title: quest.title,
            description: quest.description,
            target: quest.target,
            reward: quest.reward,
            type: quest.type,
            activities: [...quest.activities],
            progress: 0,
            completed: false,
            claimed: false
        }));
    } else {
        return DEFAULT_DAILY_QUESTS.map(quest => ({
            id: quest.id,
            title: quest.title,
            description: quest.description,
            target: quest.target,
            reward: quest.reward,
            type: quest.type,
            activities: [...quest.activities],
            progress: 0,
            completed: false,
            claimed: false
        }));
    }
}

// Middleware Autentikasi JWT - diperbaiki error handling
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            message: 'Access token required', 
            code: 'TOKEN_MISSING' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);
            
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ 
                    message: 'Token has expired', 
                    code: 'TOKEN_EXPIRED' 
                });
            } else if (err.name === 'JsonWebTokenError') {
                return res.status(403).json({ 
                    message: 'Invalid token format', 
                    code: 'TOKEN_INVALID' 
                });
            } else {
                return res.status(403).json({ 
                    message: 'Token verification failed', 
                    code: 'TOKEN_VERIFICATION_FAILED' 
                });
            }
        }
        
        req.user = user;
        next();
    });
};

// Middleware untuk memeriksa apakah user adalah admin
const authorizeAdmin = async (req, res, next) => {
    try {
        // Periksa role dari token JWT
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Admin access required', code: 'ADMIN_REQUIRED' });
        }
        next();
    } catch (error) {
        console.error('Admin authorization error:', error);
        res.status(500).json({ message: 'Internal server error during authorization', code: 'INTERNAL_ERROR' });
    }
};

// Utility function untuk validasi ObjectId
const isValidObjectId = (id) => {
    return mongoose.Types.ObjectId.isValid(id);
};

// Health Check Endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// API Routes

// Register User - diperbaiki validasi dan error handling
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validasi input yang lebih ketat
        if (!username || !email || !password) {
            return res.status(400).json({ 
                message: 'All fields are required', 
                code: 'MISSING_FIELDS' 
            });
        }

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ 
                message: 'Username must be between 3-20 characters', 
                code: 'INVALID_USERNAME_LENGTH' 
            });
        }

        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            return res.status(400).json({ 
                message: 'Username can only contain letters, numbers, underscore and dash', 
                code: 'INVALID_USERNAME_FORMAT' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                message: 'Password must be at least 6 characters', 
                code: 'INVALID_PASSWORD_LENGTH' 
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ 
                message: 'Please enter a valid email address', 
                code: 'INVALID_EMAIL_FORMAT' 
            });
        }

        // Cek user sudah ada
        const existingUser = await User.findOne({
            $or: [
                { username: username },
                { email: email.toLowerCase() }
            ]
        });

        if (existingUser) {
            const field = existingUser.username === username ? 'username' : 'email';
            return res.status(400).json({ 
                message: `${field} already exists`, 
                code: 'DUPLICATE_FIELD',
                field: field
            });
        }

        // Hash password
        const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Buat user baru dengan daily quests
        const user = new User({
            username: username.trim(),
            email: email.toLowerCase().trim(),
            password: hashedPassword,
            dailyQuests: await createDailyQuestsForUser(), // Use async function
            lastQuestReset: new Date(),
            role: 'user' // Default role for new registrations
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user._id.toString(), 
                username: user.username, 
                level: user.level,
                role: user.role // Sertakan role dalam token
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                statPoints: user.statPoints,
                stats: user.stats,
                dailyQuests: user.dailyQuests,
                activities: [],
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        
        if (error.name === 'ValidationError') {
            const field = Object.keys(error.errors)[0];
            const message = error.errors[field].message;
            return res.status(400).json({ 
                message: message, 
                code: 'VALIDATION_ERROR',
                field: field
            });
        }
        
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({ 
                message: `${field} already exists`, 
                code: 'DUPLICATE_FIELD',
                field: field
            });
        }
        
        res.status(500).json({ 
            message: 'Registration failed', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Login User - diperbaiki validasi
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validasi input
        if (!username || !password) {
            return res.status(400).json({ 
                message: 'Username and password are required', 
                code: 'MISSING_CREDENTIALS' 
            });
        }

        // Cari user by username atau email
        const user = await User.findOne({ 
            $or: [
                { username: username.trim() }, 
                { email: username.toLowerCase().trim() }
            ],
            isActive: true 
        });

        if (!user) {
            return res.status(400).json({ 
                message: 'Invalid credentials', 
                code: 'INVALID_CREDENTIALS' 
            });
        }

        // Verifikasi password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ 
                message: 'Invalid credentials', 
                code: 'INVALID_CREDENTIALS' 
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate token
        const token = jwt.sign(
            { 
                userId: user._id.toString(), 
                username: user.username, 
                level: user.level,
                role: user.role // Sertakan role dalam token
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                statPoints: user.statPoints,
                stats: user.stats,
                activities: user.activities.slice(-10).reverse(), // Ambil 10 aktivitas terakhir
                dailyQuests: user.dailyQuests,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            message: 'Login failed', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Admin Login (New Endpoint)
app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required', code: 'MISSING_CREDENTIALS' });
        }

        const user = await User.findOne({ username: username.trim(), isActive: true });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
        }

        // Check if user has 'admin' role
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized for admin access', code: 'NOT_ADMIN' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
        }

        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign(
            { userId: user._id.toString(), username: user.username, level: user.level, role: user.role }, // Sertakan role
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Shorter expiry for admin sessions
        );

        res.json({
            message: 'Admin login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                level: user.level,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Admin login failed', code: 'INTERNAL_ERROR', error: process.env.NODE_ENV !== 'production' ? error.message : undefined });
    }
});


// Get User Profile - diperbaiki validasi ID
app.get('/api/profile/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Validasi ObjectId
        if (!isValidObjectId(id)) {
            return res.status(400).json({ 
                message: 'Invalid user ID format', 
                code: 'INVALID_ID_FORMAT' 
            });
        }

        // Verifikasi user hanya bisa mengakses profile sendiri
        if (req.user.userId !== id) {
            return res.status(403).json({ 
                message: 'Unauthorized access', 
                code: 'UNAUTHORIZED' 
            });
        }

        const user = await User.findById(id).select('-password');
        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        // Reset daily quests jika sudah lewat hari - diperbaiki logic
        const now = new Date();
        const lastReset = new Date(user.lastQuestReset);
        const isNewDay = now.toDateString() !== lastReset.toDateString();
        
        if (isNewDay) {
            console.log(`Resetting daily quests for user: ${user.username}`);
            
            user.dailyQuests = await createDailyQuestsForUser(); // Use async function
            user.lastQuestReset = now;
            await user.save();
        }

        res.json({
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                statPoints: user.statPoints,
                stats: user.stats,
                activities: user.activities.slice(-10).reverse(), // 10 aktivitas terakhir
                dailyQuests: user.dailyQuests,
                lastQuestReset: user.lastQuestReset,
                lastLogin: user.lastLogin,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ 
            message: 'Failed to get profile', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Update User Profile - diperbaiki validasi
app.put('/api/profile/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Validasi ObjectId
        if (!isValidObjectId(id)) {
            return res.status(400).json({ 
                message: 'Invalid user ID format', 
                code: 'INVALID_ID_FORMAT' 
            });
        }

        // Verifikasi user hanya bisa mengupdate profile sendiri
        if (req.user.userId !== id) {
            return res.status(403).json({ 
                message: 'Unauthorized access', 
                code: 'UNAUTHORIZED' 
            });
        }

        const { dailyQuests, stats, ...otherUpdates } = req.body;

        // Validasi data yang boleh diupdate
        const allowedUpdates = ['dailyQuests', 'stats']; // Only allow these to be updated directly
        const updates = {};

        if (dailyQuests) {
            // Validasi struktur dailyQuests
            if (!Array.isArray(dailyQuests)) {
                return res.status(400).json({ 
                    message: 'Daily quests must be an array', 
                    code: 'INVALID_DAILY_QUESTS_FORMAT' 
                });
            }
            updates.dailyQuests = dailyQuests;
        }

        if (stats) {
            // Validasi stats
            const validStatNames = ['str', 'agi', 'int', 'stm', 'vit', 'per'];
            const invalidStats = Object.keys(stats).filter(stat => !validStatNames.includes(stat));
            
            if (invalidStats.length > 0) {
                return res.status(400).json({ 
                    message: `Invalid stat names: ${invalidStats.join(', ')}`, 
                    code: 'INVALID_STAT_NAMES' 
                });
            }
            
            updates.stats = stats;
        }

        // Update user
        const user = await User.findByIdAndUpdate(
            id,
            updates,
            { 
                new: true, 
                runValidators: true,
                select: '-password'
            }
        );

        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                statPoints: user.statPoints,
                stats: user.stats,
                dailyQuests: user.dailyQuests,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        
        if (error.name === 'ValidationError') {
            const field = Object.keys(error.errors)[0];
            const message = error.errors[field].message;
            return res.status(400).json({ 
                message: message, 
                code: 'VALIDATION_ERROR',
                field: field
            });
        }
        
        res.status(500).json({ 
            message: 'Failed to update profile', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Add Activity - diperbaiki logic quest progress
app.post('/api/activity', authenticateToken, async (req, res) => {
    try {
        const { name, duration, intensity, reps } = req.body;

        // Validasi input yang lebih ketat
        if (!name || !duration || !intensity) {
            return res.status(400).json({ 
                message: 'Name, duration and intensity are required', 
                code: 'MISSING_FIELDS' 
            });
        }

        const user = await User.findById(req.user.userId);
        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        // Cek cooldown
        if (user.lastActivity) {
            const cooldownEnd = new Date(user.lastActivity.getTime() + 5 * 60 * 1000); // 5 menit
            if (new Date() < cooldownEnd) {
                const remainingMinutes = Math.ceil((cooldownEnd - new Date()) / (60 * 1000));
                return res.status(429).json({ 
                    message: `Please wait ${remainingMinutes} minutes before logging another activity`, 
                    code: 'ACTIVITY_COOLDOWN' 
                });
            }
        }

        // Hitung EXP
        const intensityMultiplier = {
            low: 1.5,
            medium: 2.5,
            high: 3.5
        };
        
        let expGained = Math.floor(duration * intensityMultiplier[intensity]);
        if (reps && reps > 0) {
            expGained += Math.floor(reps * 0.5);
        }

        // Update quest progress
        const updatedQuests = [...user.dailyQuests];
        const activityLower = name.toLowerCase().trim();
        
        updatedQuests.forEach(quest => {
            if (quest.completed || quest.claimed) return;

            let progressAdded = 0;
            
            switch (quest.type) {
                case 'duration':
                    if (quest.activities.length === 0 || 
                        quest.activities.some(qActivity => 
                            activityLower.includes(qActivity.toLowerCase()))) {
                        progressAdded = duration;
                    }
                    break;
                case 'total_duration':
                    progressAdded = duration;
                    break;
                case 'reps':
                    if (reps && reps > 0) {
                        progressAdded = reps;
                    }
                    break;
                case 'sessions':
                    progressAdded = 1;
                    break;
            }

            if (progressAdded > 0) {
                quest.progress = Math.min(quest.progress + progressAdded, quest.target);
                quest.completed = quest.progress >= quest.target;
            }
        });

        // Update level dan stats
        let levelsGained = 0;
        let newExp = user.exp + expGained;
        let newLevel = user.level;
        let newExpToNext = user.expToNext;
        let newStatPoints = user.statPoints;
        
        while (newExp >= newExpToNext && levelsGained < 10) {
            newExp -= newExpToNext;
            newLevel++;
            newStatPoints += 5;
            newExpToNext = Math.floor(newExpToNext * 1.15);
            levelsGained++;
        }

        // Update user
        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            {
                exp: newExp,
                level: newLevel,
                expToNext: newExpToNext,
                statPoints: newStatPoints,
                $push: {
                    activities: {
                        name: name.trim(),
                        duration: duration,
                        intensity: intensity,
                        reps: reps || 0,
                        exp: expGained,
                        date: new Date()
                    }
                },
                dailyQuests: updatedQuests,
                lastActivity: new Date()
            },
            { new: true }
        );

        res.json({
            message: 'Activity logged successfully',
            expGained,
            levelsGained,
            activity: updatedUser.activities[updatedUser.activities.length - 1],
            user: {
                id: updatedUser._id,
                username: updatedUser.username,
                level: updatedUser.level,
                exp: updatedUser.exp,
                expToNext: updatedUser.expToNext,
                statPoints: updatedUser.statPoints,
                stats: updatedUser.stats,
                activities: updatedUser.activities.slice(-10).reverse(),
                dailyQuests: updatedUser.dailyQuests,
                role: updatedUser.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Activity error:', error);
        res.status(500).json({ 
            message: 'Failed to log activity', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Claim Quest Reward - diperbaiki validasi
app.post('/api/quests/claim', authenticateToken, async (req, res) => {
    try {
        const { questId } = req.body;

        if (!questId || typeof questId !== 'string') {
            return res.status(400).json({ 
                message: 'Valid quest ID is required', 
                code: 'MISSING_QUEST_ID' 
            });
        }

        const user = await User.findById(req.user.userId);
        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        const quest = user.dailyQuests.find(q => q.id === questId);
        if (!quest) {
            return res.status(404).json({ 
                message: 'Quest not found', 
                code: 'QUEST_NOT_FOUND' 
            });
        }

        if (!quest.completed) {
            return res.status(400).json({ 
                message: 'Quest not completed yet', 
                code: 'QUEST_INCOMPLETE' 
            });
        }

        if (quest.claimed) {
            return res.status(400).json({ 
                message: 'Quest reward already claimed', 
                code: 'QUEST_ALREADY_CLAIMED' 
            });
        }

        // Berikan reward
        quest.claimed = true;
        user.exp += quest.reward;

        // Cek level up setelah dapat reward
        let levelsGained = 0;
        while (user.exp >= user.expToNext && levelsGained < 10) {
            user.exp -= user.expToNext;
            user.level++;
            user.statPoints += 5;
            user.expToNext = Math.floor(user.expToNext * 1.15);
            levelsGained++;
        }

        await user.save();

        res.json({
            message: 'Quest reward claimed successfully',
            reward: quest.reward,
            levelsGained,
            questTitle: quest.title,
            user: {
                id: user._id,
                username: user.username,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                statPoints: user.statPoints,
                stats: user.stats,
                dailyQuests: user.dailyQuests,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Claim quest error:', error);
        res.status(500).json({ 
            message: 'Failed to claim quest reward', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Update Stats - diperbaiki validasi
app.post('/api/stats', authenticateToken, async (req, res) => {
    try {
        const { statName } = req.body;

        const validStats = ['str', 'agi', 'int', 'stm', 'vit', 'per'];
        if (!statName || !validStats.includes(statName)) {
            return res.status(400).json({ 
                message: 'Invalid stat name. Valid stats: ' + validStats.join(', '), 
                code: 'INVALID_STAT',
                validStats: validStats
            });
        }

        const user = await User.findById(req.user.userId);
        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        if (user.statPoints <= 0) {
            return res.status(400).json({ 
                message: 'No stat points available', 
                code: 'NO_STAT_POINTS' 
            });
        }

        // Cek batas maksimal stat
        if (user.stats[statName] >= 999) {
            return res.status(400).json({ 
                message: 'Stat already at maximum value (999)', 
                code: 'STAT_AT_MAXIMUM' 
            });
        }

        // Update stat
        user.stats[statName]++;
        user.statPoints--;

        await user.save();

        res.json({
            message: 'Stat increased successfully',
            statName: statName,
            newValue: user.stats[statName],
            user: {
                id: user._id,
                username: user.username,
                level: user.level,
                statPoints: user.statPoints,
                stats: user.stats,
                role: user.role // Sertakan role dalam respons
            }
        });

    } catch (error) {
        console.error('Stat update error:', error);
        res.status(500).json({ 
            message: 'Failed to update stat', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Leaderboard - diperbaiki caching dan error handling
let leaderboardCache = null;
let leaderboardCacheTime = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 menit

app.get('/api/leaderboard', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const offset = parseInt(req.query.offset) || 0;

        // Validasi parameters
        if (limit < 1 || limit > 100) {
            return res.status(400).json({ 
                message: 'Limit must be between 1 and 100', 
                code: 'INVALID_LIMIT' 
            });
        }

        if (offset < 0) {
            return res.status(400).json({ 
                message: 'Offset cannot be negative', 
                code: 'INVALID_OFFSET' 
            });
        }

        const cacheKey = `${limit}-${offset}`;
        
        // Gunakan cache jika masih valid dan untuk request yang sama
        if (leaderboardCache && 
            leaderboardCache.key === cacheKey && 
            (Date.now() - leaderboardCacheTime) < CACHE_DURATION) {
            return res.json({ 
                leaderboard: leaderboardCache.data,
                cached: true,
                cacheAge: Date.now() - leaderboardCacheTime
            });
        }

        // Ambil top users (hanya user dengan role 'user')
        const topUsers = await User.find({ isActive: true, role: 'user' })
            .sort({ level: -1, exp: -1, username: 1 }) // Sort by level desc, exp desc, username asc
            .skip(offset)
            .limit(limit)
            .select('username level exp stats dailyQuests createdAt')
            .lean();

        // Get total count untuk pagination (hanya user dengan role 'user')
        const totalUsers = await User.countDocuments({ isActive: true, role: 'user' });

        // Format data leaderboard
        const leaderboard = topUsers.map((user, index) => ({
            rank: offset + index + 1,
            username: user.username,
            level: user.level,
            exp: user.exp,
            totalStats: Object.values(user.stats).reduce((a, b) => a + b, 0),
            completedQuests: user.dailyQuests ? user.dailyQuests.filter(q => q.completed).length : 0,
            claimedQuests: user.dailyQuests ? user.dailyQuests.filter(q => q.claimed).length : 0,
            joinDate: user.createdAt
        }));

        // Update cache
        leaderboardCache = {
            key: cacheKey,
            data: leaderboard
        };
        leaderboardCacheTime = Date.now();

        res.json({ 
            leaderboard,
            pagination: {
                total: totalUsers,
                limit,
                offset,
                hasMore: offset + limit < totalUsers
            },
            cached: false
        });

    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ 
            message: 'Failed to get leaderboard', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Get User Statistics
app.get('/api/stats/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user || !user.isActive) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        // Hitung statistik user
        const totalActivities = user.activities.length;
        const totalDuration = user.activities.reduce((sum, activity) => sum + activity.duration, 0);
        const totalReps = user.activities.reduce((sum, activity) => sum + (activity.reps || 0), 0);
        const avgDuration = totalActivities > 0 ? Math.round(totalDuration / totalActivities) : 0;
        
        // Statistik minggu ini
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        const weeklyActivities = user.activities.filter(activity => new Date(activity.date) >= weekAgo);
        const weeklyDuration = weeklyActivities.reduce((sum, activity) => sum + activity.duration, 0);

        // Quest statistics
        const completedQuests = user.dailyQuests.filter(q => q.completed).length;
        const claimedQuests = user.dailyQuests.filter(q => q.claimed).length;
        const questCompletionRate = user.dailyQuests.length > 0 ? 
            Math.round((completedQuests / user.dailyQuests.length) * 100) : 0;

        res.json({
            user: {
                id: user._id,
                username: user.username,
                level: user.level,
                exp: user.exp,
                expToNext: user.expToNext,
                role: user.role // Sertakan role dalam respons
            },
            statistics: {
                totalActivities,
                totalDuration,
                totalReps,
                avgDuration,
                weeklyActivities: weeklyActivities.length,
                weeklyDuration,
                completedQuests,
                claimedQuests,
                questCompletionRate
            },
            achievements: {
                totalStats: Object.values(user.stats).reduce((a, b) => a + b, 0),
                highestStat: Math.max(...Object.values(user.stats)),
                accountAge: Math.floor((Date.now() - user.createdAt) / (1000 * 60 * 60 * 24)) // days
            }
        });

    } catch (error) {
        console.error('User stats error:', error);
        res.status(500).json({ 
            message: 'Failed to get user statistics', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Update Quests Progress (This endpoint is not used by frontend, but kept for completeness)
app.post('/api/quests', authenticateToken, async (req, res) => {
    try {
        const { quests } = req.body;

        if (!quests || !Array.isArray(quests)) {
            return res.status(400).json({ 
                message: 'Invalid quests data', 
                code: 'INVALID_QUESTS_DATA' 
            });
        }

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { dailyQuests: quests },
            { new: true, runValidators: true }
        );

        if (!user) {
            return res.status(404).json({ 
                message: 'User not found', 
                code: 'USER_NOT_FOUND' 
            });
        }

        res.json({
            message: 'Quests updated successfully',
            quests: user.dailyQuests
        });

    } catch (error) {
        console.error('Update quests error:', error);
        res.status(500).json({ 
            message: 'Failed to update quests', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Reset Daily Quests (Admin) - diperbaiki authorization
app.post('/api/quests/reset', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // Reset quest semua user
        const result = await User.updateMany(
            { isActive: true },
            {
                $set: {
                    dailyQuests: await createDailyQuestsForUser(), // Use async function
                    lastQuestReset: new Date()
                }
            }
        );

        // Clear leaderboard cache
        leaderboardCache = null;

        res.json({
            message: 'Daily quests reset successfully for all users',
            usersAffected: result.modifiedCount,
            resetBy: req.user.username,
            resetTime: new Date().toISOString()
        });

    } catch (error) {
        console.error('Reset quests error:', error);
        res.status(500).json({ 
            message: 'Failed to reset quests', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Get System Info (Admin)
app.get('/api/system', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ isActive: true });
        const totalActivities = await User.aggregate([
            { $match: { isActive: true } },
            { $project: { activityCount: { $size: '$activities' } } },
            { $group: { _id: null, total: { $sum: '$activityCount' } } }
        ]);

        const systemInfo = {
            database: {
                status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                host: mongoose.connection.host,
                name: mongoose.connection.name
            },
            statistics: {
                totalUsers,
                totalActivities: totalActivities[0]?.total || 0,
                averageLevel: await User.aggregate([
                    { $match: { isActive: true } },
                    { $group: { _id: null, avgLevel: { $avg: '$level' } } }
                ]).then(result => Math.round(result[0]?.avgLevel || 1))
            },
            server: {
                uptime: process.uptime(),
                nodeVersion: process.version,
                environment: process.env.NODE_ENV || 'development'
            }
        };

        res.json(systemInfo);

    } catch (error) {
        console.error('System info error:', error);
        res.status(500).json({ 
            message: 'Failed to get system info', 
            code: 'INTERNAL_ERROR',
            error: process.env.NODE_ENV !== 'production' ? error.message : undefined
        });
    }
});

// Admin Endpoints for User Management
app.get('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const users = await User.find({}).select('-password').lean();
        res.json({ users: users.map(user => ({
            id: user._id,
            username: user.username,
            email: user.email,
            level: user.level,
            status: user.isActive ? 'active' : 'inactive', // Assuming isActive maps to status
            last_active: user.lastLogin, // Using lastLogin as last_active
            role: user.role // Sertakan role
        }))});
    } catch (error) {
        console.error('Admin get all users error:', error);
        res.status(500).json({ message: 'Failed to fetch users', code: 'INTERNAL_ERROR' });
    }
});

app.put('/api/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { username, level, status, role } = req.body; // Tambahkan role

        if (!isValidObjectId(id)) {
            return res.status(400).json({ message: 'Invalid user ID format', code: 'INVALID_ID_FORMAT' });
        }

        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found', code: 'USER_NOT_FOUND' });
        }

        user.username = username || user.username;
        user.level = level !== undefined ? level : user.level;
        user.isActive = status === 'active'; // Map status back to isActive
        user.role = role || user.role; // Update role

        await user.save();
        res.json({ message: 'User updated successfully', user: { id: user._id, username: user.username, level: user.level, status: user.isActive ? 'active' : 'inactive', role: user.role } });
    } catch (error) {
        console.error('Admin update user error:', error);
        res.status(500).json({ message: 'Failed to update user', code: 'INTERNAL_ERROR' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return res.status(400).json({ message: 'Invalid user ID format', code: 'INVALID_ID_FORMAT' });
        }

        const result = await User.findByIdAndDelete(id);
        if (!result) {
            return res.status(404).json({ message: 'User not found', code: 'USER_NOT_FOUND' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ message: 'Failed to delete user', code: 'INTERNAL_ERROR' });
    }
});

// Admin Endpoints for Activity Types Management
app.get('/api/admin/activity-types', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const activityTypes = await ActivityType.find({});
        res.json({ activityTypes: activityTypes.map(type => ({
            id: type._id,
            name: type.name,
            base_exp: type.base_exp,
            category: type.category
        }))});
    } catch (error) {
        console.error('Admin get activity types error:', error);
        res.status(500).json({ message: 'Failed to fetch activity types', code: 'INTERNAL_ERROR' });
    }
});

app.post('/api/admin/activity-types', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { name, base_exp, category } = req.body;
        const newActivityType = new ActivityType({ name, base_exp, category });
        await newActivityType.save();
        res.status(201).json({ message: 'Activity type created successfully', activityType: newActivityType });
    } catch (error) {
        console.error('Admin create activity type error:', error);
        res.status(500).json({ message: 'Failed to create activity type', code: 'INTERNAL_ERROR' });
    }
});

app.put('/api/admin/activity-types/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, base_exp, category } = req.body;

        if (!isValidObjectId(id)) {
            return res.status(400).json({ message: 'Invalid activity type ID format', code: 'INVALID_ID_FORMAT' });
        }

        const updatedActivityType = await ActivityType.findByIdAndUpdate(
            id,
            { name, base_exp, category },
            { new: true, runValidators: true }
        );
        if (!updatedActivityType) {
            return res.status(404).json({ message: 'Activity type not found', code: 'ACTIVITY_TYPE_NOT_FOUND' });
        }
        res.json({ message: 'Activity type updated successfully', activityType: updatedActivityType });
    } catch (error) {
        console.error('Admin update activity type error:', error);
        res.status(500).json({ message: 'Failed to update activity type', code: 'INTERNAL_ERROR' });
    }
});

app.delete('/api/admin/activity-types/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidObjectId(id)) {
            return res.status(400).json({ message: 'Invalid activity type ID format', code: 'INVALID_ID_FORMAT' });
        }

        const result = await ActivityType.findByIdAndDelete(id);
        if (!result) {
            return res.status(404).json({ message: 'Activity type not found', code: 'ACTIVITY_TYPE_NOT_FOUND' });
        }
        res.json({ message: 'Activity type deleted successfully' });
    } catch (error) {
        console.error('Admin delete activity type error:', error);
        res.status(500).json({ message: 'Failed to delete activity type', code: 'INTERNAL_ERROR' });
    }
});

// Admin Endpoints for Quest Management
app.get('/api/admin/quests', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const quests = await Quest.find({});
        res.json({ quests: quests.map(quest => ({
            id: quest.id,
            title: quest.title,
            description: quest.description,
            type: quest.type,
            target: quest.target,
            reward: quest.reward,
            activities: quest.activities
        }))});
    } catch (error) {
        console.error('Admin get quests error:', error);
        res.status(500).json({ message: 'Failed to fetch quests', code: 'INTERNAL_ERROR' });
    }
});

app.post('/api/admin/quests', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id, title, description, type, target, reward, activities } = req.body;
        const newQuest = new Quest({ id, title, description, type, target, reward, activities });
        await newQuest.save();
        res.status(201).json({ message: 'Quest created successfully', quest: newQuest });
    } catch (error) {
        console.error('Admin create quest error:', error);
        res.status(500).json({ message: 'Failed to create quest', code: 'INTERNAL_ERROR' });
    }
});

app.put('/api/admin/quests/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, type, target, reward, activities } = req.body;

        const updatedQuest = await Quest.findOneAndUpdate(
            { id: id }, // Find by custom string ID
            { title, description, type, target, reward, activities },
            { new: true, runValidators: true }
        );
        if (!updatedQuest) {
            return res.status(404).json({ message: 'Quest not found', code: 'QUEST_NOT_FOUND' });
        }
        res.json({ message: 'Quest updated successfully', quest: updatedQuest });
    } catch (error) {
        console.error('Admin update quest error:', error);
        res.status(500).json({ message: 'Failed to update quest', code: 'INTERNAL_ERROR' });
    }
});

app.delete('/api/admin/quests/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await Quest.findOneAndDelete({ id: id }); // Find by custom string ID
        if (!result) {
            return res.status(404).json({ message: 'Quest not found', code: 'QUEST_NOT_FOUND' });
        }
        res.json({ message: 'Quest deleted successfully' });
    } catch (error) {
        console.error('Admin delete quest error:', error);
        res.status(500).json({ message: 'Failed to delete quest', code: 'INTERNAL_ERROR' });
    }
});


// API Documentation
app.get('/api', (req, res) => {
    res.json({
        name: 'VR Fitness System API',
        version: '1.0.0',
        description: 'A gamified fitness tracking system with RPG elements',
        endpoints: {
            authentication: {
                'POST /api/register': 'Register new user',
                'POST /api/login': 'Login user',
                'POST /api/admin/login': 'Login admin user'
            },
            user: {
                'GET /api/profile/:id': 'Get user profile',
                'PUT /api/profile/:id': 'Update user profile',
                'POST /api/stats': 'Increase stat points'
            },
            activities: {
                'POST /api/activity': 'Add training activity'
            },
            quests: {
                'POST /api/quests/claim': 'Claim quest reward',
                'POST /api/quests/reset': 'Reset daily quests (admin)'
            },
            leaderboard: {
                'GET /api/leaderboard': 'Get leaderboard with pagination'
            },
            admin: {
                'GET /api/admin/users': 'Get all users',
                'PUT /api/admin/users/:id': 'Update user by ID',
                'DELETE /api/admin/users/:id': 'Delete user by ID',
                'GET /api/admin/activity-types': 'Get all activity types',
                'POST /api/admin/activity-types': 'Create new activity type',
                'PUT /api/admin/activity-types/:id': 'Update activity type by ID',
                'DELETE /api/admin/activity-types/:id': 'Delete activity type by ID',
                'GET /api/admin/quests': 'Get all quests',
                'POST /api/admin/quests': 'Create new quest',
                'PUT /api/admin/quests/:id': 'Update quest by ID',
                'DELETE /api/admin/quests/:id': 'Delete quest by ID',
                'GET /api/system': 'Get system information'
            },
            health: {
                'GET /health': 'Health check endpoint'
            }
        },
        authentication: {
            type: 'Bearer Token (JWT)',
            header: 'Authorization: Bearer <token>',
            expiration: '24 hours (user), 1 hour (admin)'
        }
    });
});

// Serve Frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('Global error:', {
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    // Jangan expose error details di production
    const errorResponse = {
        message: 'Something went wrong!', 
        code: 'INTERNAL_ERROR',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
    };
    
    if (process.env.NODE_ENV !== 'production') {
        errorResponse.error = err.message;
        errorResponse.stack = err.stack;
    }
    
    res.status(500).json(errorResponse);
});

// 404 Handler untuk API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ 
        message: 'API endpoint not found', 
        code: 'ENDPOINT_NOT_FOUND',
        availableEndpoints: '/api for documentation'
    });
});

// Middleware untuk auto-reset daily quests (moved to /api/profile/:id for better context)
// This middleware is now handled within the /api/profile/:id GET route.

// Graceful Shutdown
const gracefulShutdown = (signal) => {
    console.log(`${signal} received. Shutting down gracefully...`);
    
    // Close server
    const server = app.listen(); // Get the server instance
    server.close(() => {
        console.log('HTTP server closed.');
        
        // Close database connection
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed.');
            process.exit(0);
        });
    });
    
    // Force close after 30 seconds
    setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
    console.error('Unhandled Promise Rejection:', err);
    console.error('Promise:', promise);
    // Don't exit in production, just log
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

// Start Server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📚 API docs: http://localhost:${PORT}/api`);
    console.log(`💡 Health check: http://localhost:${PORT}/health`);
});

// Handle server errors
server.on('error', (error) => {
    if (error.syscall !== 'listen') {
        throw error;
    }

    const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;

    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
});

module.exports = app;
