const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Koneksi ke MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    retryWrites: true,
    w: 'majority'
})
.then(() => console.log('✅ Connected to MongoDB for seeding'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// Schema User
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
    timestamps: false
});

const User = mongoose.model('User', userSchema);

// Schema for Activity Types (for Admin Panel) - Added
const activityTypeSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true },
    base_exp: { type: Number, required: true, min: 0 },
    category: { type: String, required: true, trim: true }
});
const ActivityType = mongoose.model('ActivityType', activityTypeSchema);

// Schema for Quests (for Admin Panel) - Added
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


// Definisi Daily Quests (now also used for seeding Quest model)
const DEFAULT_DAILY_QUESTS_TEMPLATE = [
    {
        id: 'cardio_warrior',
        title: 'Cardio Warrior',
        description: 'Complete 30 minutes of cardio training',
        target: 30,
        reward: 150,
        type: 'duration',
        activities: ['running', 'cycling', 'cardio', 'neural cardio', 'combat cardio'],
    },
    {
        id: 'strength_master',
        title: 'Strength Master',
        description: 'Complete 45 minutes of strength training',
        target: 45,
        reward: 200,
        type: 'duration',
        activities: ['strength', 'weight', 'lifting', 'combat training', 'power training'],
    },
    {
        id: 'endurance_hunter',
        title: 'Endurance Hunter',
        description: 'Train for at least 60 minutes total',
        target: 60,
        reward: 250,
        type: 'total_duration',
        activities: [],
    },
    {
        id: 'rep_champion',
        title: 'Rep Champion',
        description: 'Complete 100 repetitions in any exercise',
        target: 100,
        reward: 180,
        type: 'reps',
        activities: [],
    },
    {
        id: 'consistency_king',
        title: 'Consistency King',
        description: 'Complete 3 different training sessions',
        target: 3,
        reward: 300,
        type: 'sessions',
        activities: [],
    }
];

// Function untuk membuat deep copy dari dailyQuests
async function createDailyQuestsForUser () {
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
        return DEFAULT_DAILY_QUESTS_TEMPLATE.map(quest => ({
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


// Sample Activity Types - Added
const sampleActivityTypes = [
    { name: 'Combat Training', base_exp: 10, category: 'Strength' },
    { name: 'Neural Cardio', base_exp: 8, category: 'Cardio' },
    { name: 'Mana Meditation', base_exp: 5, category: 'Intelligence' },
    { name: 'Endurance Run', base_exp: 7, category: 'Stamina' },
    { name: 'Agility Drills', base_exp: 9, category: 'Agility' },
    { name: 'Perception Training', base_exp: 6, category: 'Perception' },
];

// Sample Users dengan Daily Quests
const sampleUsers = [
    {
        username: 'SungJinWoo',
        email: 'shadowmonarch@hunter.guild',
        password: 'hunter123',
        level: 100,
        exp: 999,
        expToNext: 10000,
        statPoints: 25,
        stats: {
            str: 999,
            agi: 999,
            int: 999,
            stm: 999,
            vit: 999,
            per: 999
        },
        activities: [
            { name: 'Shadow Army Training', duration: 120, intensity: 'high', reps: 200, exp: 500, date: new Date('2024-01-15') },
            { name: 'Dimensional Rift Conquest', duration: 180, intensity: 'high', reps: 300, exp: 800, date: new Date('2024-01-20') },
            { name: 'Nation-Level Beast Hunt', duration: 240, intensity: 'high', reps: 500, exp: 1200, date: new Date('2024-01-25') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'GoGunhee',
        email: 'chairman@hunter.association',
        password: 'hunter123',
        level: 85,
        exp: 2800,
        expToNext: 8500,
        statPoints: 15,
        stats: {
            str: 450,
            agi: 380,
            int: 520,
            stm: 480,
            vit: 500,
            per: 460
        },
        activities: [
            { name: 'Association Leadership Training', duration: 90, intensity: 'medium', reps: 150, exp: 300, date: new Date('2024-01-10') },
            { name: 'S-Rank Gate Supervision', duration: 150, intensity: 'high', reps: 100, exp: 450, date: new Date('2024-01-18') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'ThomasAndre',
        email: 'goliath@scavenger.guild',
        password: 'hunter123',
        level: 78,
        exp: 1200,
        expToNext: 7200,
        statPoints: 12,
        stats: {
            str: 650,
            agi: 280,
            int: 320,
            stm: 580,
            vit: 620,
            per: 350
        },
        activities: [
            { name: 'Titan Strength Training', duration: 100, intensity: 'high', reps: 120, exp: 350, date: new Date('2024-01-12') },
            { name: 'Guild Combat Drills', duration: 120, intensity: 'medium', reps: 200, exp: 400, date: new Date('2024-01-19') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'LiuZhigang',
        email: 'flame.emperor@hunters.cn',
        password: 'hunter123',
        level: 72,
        exp: 800,
        expToNext: 6500,
        statPoints: 8,
        stats: {
            str: 420,
            agi: 480,
            int: 520,
            stm: 450,
            vit: 380,
            per: 440
        },
        activities: [
            { name: 'Fire Magic Mastery', duration: 85, intensity: 'medium', reps: 80, exp: 320, date: new Date('2024-01-14') },
            { name: 'Elemental Combat Training', duration: 110, intensity: 'high', reps: 150, exp: 380, date: new Date('2024-01-21') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'ChaShinHye',
        email: 'healer@white.tiger.guild',
        password: 'hunter123',
        level: 68,
        exp: 1500,
        expToNext: 6000,
        statPoints: 10,
        stats: {
            str: 250,
            agi: 380,
            int: 580,
            stm: 420,
            vit: 450,
            per: 520
        },
        activities: [
            { name: 'Healing Magic Enhancement', duration: 70, intensity: 'low', reps: 60, exp: 280, date: new Date('2024-01-16') },
            { name: 'Support Skill Training', duration: 95, intensity: 'medium', reps: 100, exp: 350, date: new Date('2024-01-23') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'BaikYoonho',
        email: 'whitesnake@flame.guild',
        password: 'hunter123',
        level: 65,
        exp: 900,
        expToNext: 5800,
        statPoints: 6,
        stats: {
            str: 380,
            agi: 420,
            int: 350,
            stm: 400,
            vit: 360,
            per: 390
        },
        activities: [
            { name: 'Speed Enhancement Training', duration: 75, intensity: 'medium', reps: 90, exp: 270, date: new Date('2024-01-17') },
            { name: 'Agility Combat Drills', duration: 90, intensity: 'high', reps: 120, exp: 320, date: new Date('2024-01-24') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    {
        username: 'HwangDongsu',
        email: 'flame.dragon@hunters.usa',
        password: 'hunter123',
        level: 58,
        exp: 400,
        expToNext: 4200,
        statPoints: 4,
        stats: {
            str: 340,
            agi: 320,
            int: 280,
            stm: 360,
            vit: 330,
            per: 310
        },
        activities: [
            { name: 'Fire Breath Training', duration: 80, intensity: 'medium', reps: 70, exp: 290, date: new Date('2024-01-18') },
            { name: 'Dragon Form Practice', duration: 100, intensity: 'high', reps: 110, exp: 360, date: new Date('2024-01-25') }
        ],
        dailyQuests: [], // Will be populated by createDailyQuestsForUser
        lastQuestReset: new Date(),
        role: 'user' // Default role
    },
    // --- Admin Accounts ---
    {
        username: 'AdminOne',
        email: 'admin1@system.com',
        password: 'adminpassword', // Use a strong password in production
        level: 999, // High level for display, but role determines admin status
        exp: 0, expToNext: 100, statPoints: 0,
        stats: { str: 10, agi: 10, int: 10, stm: 10, vit: 10, per: 10 },
        activities: [],
        dailyQuests: [],
        lastQuestReset: new Date(),
        role: 'admin' // Admin role
    },
    {
        username: 'AdminTwo',
        email: 'admin2@system.com',
        password: 'adminpassword',
        level: 999,
        exp: 0, expToNext: 100, statPoints: 0,
        stats: { str: 10, agi: 10, int: 10, stm: 10, vit: 10, per: 10 },
        activities: [],
        dailyQuests: [],
        lastQuestReset: new Date(),
        role: 'admin'
    },
    {
        username: 'AdminThree',
        email: 'admin3@system.com',
        password: 'adminpassword',
        level: 999,
        exp: 0, expToNext: 100, statPoints: 0,
        stats: { str: 10, agi: 10, int: 10, stm: 10, vit: 10, per: 10 },
        activities: [],
        dailyQuests: [],
        lastQuestReset: new Date(),
        role: 'admin'
    }
];

async function seedDatabase() {
    try {
        console.log('🌱 Starting database seeding process...');
        
        // Hapus data lama
        const deleteUsersResult = await User.deleteMany({});
        console.log(`🗑️  Cleared ${deleteUsersResult.deletedCount} existing user records`);
        const deleteActivityTypesResult = await ActivityType.deleteMany({});
        console.log(`🗑️  Cleared ${deleteActivityTypesResult.deletedCount} existing activity type records`);
        const deleteQuestsResult = await Quest.deleteMany({});
        console.log(`🗑️  Cleared ${deleteQuestsResult.deletedCount} existing quest records`);

        // Seed Activity Types
        console.log('🏋️‍♀️ Seeding Activity Types...');
        const createdActivityTypes = await ActivityType.insertMany(sampleActivityTypes);
        console.log(`✅ Successfully created ${createdActivityTypes.length} sample activity types`);

        // Seed Quests (from DEFAULT_DAILY_QUESTS_TEMPLATE)
        console.log('📜 Seeding Quests...');
        const createdQuests = await Quest.insertMany(DEFAULT_DAILY_QUESTS_TEMPLATE);
        console.log(`✅ Successfully created ${createdQuests.length} sample quests`);

        // Hash password untuk semua user dan populate daily quests
        console.log('🔐 Hashing passwords and populating daily quests...');
        const hashedUsers = await Promise.all(
            sampleUsers.map(async (user) => {
                const hashedPassword = await bcrypt.hash(user.password, 12);
                return {
                    ...user,
                    password: hashedPassword,
                    createdAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
                    lastLogin: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
                    dailyQuests: await createDailyQuestsForUser() // Populate daily quests here
                };
            })
        );

        // Insert data sample satu per satu untuk error handling yang lebih baik
        console.log('👥 Creating hunter profiles...');
        const createdUsers = [];
        
        for (let i = 0; i < hashedUsers.length; i++) {
            try {
                const user = new User(hashedUsers[i]);
                const savedUser = await user.save();
                createdUsers.push(savedUser);
                console.log(`   ✅ Created: ${savedUser.username} (Level ${savedUser.level}, Role: ${savedUser.role})`);
            } catch (error) {
                console.error(`   ❌ Failed to create user ${hashedUsers[i].username}:`, error.message);
            }
        }

        console.log(`✅ Successfully created ${createdUsers.length} sample hunters`);

        // Tampilkan info login
        console.log('\n🎮 Sample login credentials (all use password: hunter123, admin use: adminpassword):');
        createdUsers.sort((a, b) => b.level - a.level).forEach((user, index) => {
            console.log(`   ${index + 1}. ${user.username} (Level ${user.level}, Role: ${user.role})`);
        });

        // Tampilkan preview leaderboard
        console.log('\n🏆 Leaderboard Preview:');
        createdUsers.filter(u => u.role === 'user').slice(0, 5).forEach((user, index) => { // Hanya user biasa di leaderboard
            const totalStats = Object.values(user.stats).reduce((sum, stat) => sum + stat, 0);
            const rank = index === 0 ? '👑' : index === 1 ? '🥈' : index === 2 ? '🥉' : `${index + 1}.`;
            console.log(`   ${rank} ${user.username} - Level ${user.level} | Stats: ${totalStats} | Quests: ${user.dailyQuests.length}`);
        });

        console.log('\n📊 Database Statistics:');
        console.log(`   Total Users: ${createdUsers.length}`);
        console.log(`   Total Regular Users: ${createdUsers.filter(u => u.role === 'user').length}`);
        console.log(`   Total Admin Users: ${createdUsers.filter(u => u.role === 'admin').length}`);
        console.log(`   Average Level (Users): ${Math.round(createdUsers.filter(u => u.role === 'user').reduce((sum, user) => sum + user.level, 0) / createdUsers.filter(u => u.role === 'user').length)}`);
        console.log(`   Total Daily Quests: ${createdUsers.reduce((sum, user) => sum + user.dailyQuests.length, 0)}`);
        console.log(`   Total Activity Types: ${createdActivityTypes.length}`);
        console.log(`   Total Quests in DB: ${createdQuests.length}`);


        console.log('\n🚀 VR Fitness System is ready!');
        console.log('   Run: npm start');
        console.log('   Visit: http://localhost:3000');

    } catch (error) {
        console.error('❌ Error seeding database:', error);
        process.exit(1);
    } finally {
        mongoose.connection.close();
        console.log('\n🔌 Database connection closed');
    }
}

// Handle process termination
process.on('SIGINT', () => {
    console.log('\n⚠️  Seeding process interrupted');
    mongoose.connection.close(() => {
        process.exit(0);
    });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Promise Rejection:', err);
    mongoose.connection.close(() => {
        process.exit(1);
    });
});

// Jalankan seeding
seedDatabase();
