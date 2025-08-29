const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://Malula_04:db_Deo2024@classic-maximize-pay.cuwyaoa.mongodb.net/classic-maximize-pay?retryWrites=true&w=majority';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.log('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
    fullname: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    dailyEarnings: { type: Number, default: 0 },
    bankInfo: {
        accountName: String,
        accountPhone: String,
        bankName: String
    },
    investments: [{
        planId: Number,
        amount: Number,
        startDate: Date,
        endDate: Date,
        expectedProfit: Number,
        profitReceived: { type: Number, default: 0 },
        status: { type: String, default: 'active' } // active, completed
    }],
    transactions: [{
        type: { type: String, enum: ['recharge', 'withdrawal'] },
        amount: Number,
        date: { type: Date, default: Date.now },
        status: { type: String, default: 'pending' }, // pending, approved, rejected
        paymentMethod: String,
        transactionId: String
    }],
    products: [{
        productId: Number,
        name: String,
        cost: Number,
        purchaseDate: { type: Date, default: Date.now },
        dailyEarningRate: Number,
        status: { type: String, default: 'active' } // active, completed
    }],
    team: {
        level1: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Direct referrals
        level2: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Second level
        level3: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]  // Third level
    },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    otp: String,
    otpExpires: Date
}, { timestamps: true });

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true }
});

const DailyNotificationSchema = new mongoose.Schema({
    message: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const TaskSchema = new mongoose.Schema({
    message: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const DailyNotification = mongoose.model('DailyNotification', DailyNotificationSchema);
const Task = mongoose.model('Task', TaskSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        
        if (!admin) {
            return res.status(404).json({ message: 'Admin not found' });
        }
        
        req.admin = admin;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

// Routes

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullname, username, email, phone, password, referralCode } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [{ email }, { username }, { phone }]
        });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email, username or phone' });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new user
        const newUser = new User({
            fullname,
            username,
            email,
            phone,
            password: hashedPassword
        });

        // Handle referral if provided
        if (referralCode) {
            const referrer = await User.findById(referralCode);
            if (referrer) {
                newUser.referredBy = referrer._id;
                referrer.team.level1.push(newUser._id);
                await referrer.save();
            }
        }

        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                balance: user.balance,
                totalProfit: user.totalProfit,
                dailyEarnings: user.dailyEarnings
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify token endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        balance: req.user.balance,
        totalProfit: req.user.totalProfit,
        dailyEarnings: req.user.dailyEarnings
    });
});

// Forgot password - Send OTP
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { phone } = req.body;

        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ message: 'User not found with this phone number' });
        }

        // Generate OTP (6 digits)
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        user.otp = otp;
        user.otpExpires = otpExpires;
        await user.save();

        // In a real application, you would send this OTP via SMS
        // For demo purposes, we'll just return it
        console.log(`OTP for ${phone}: ${otp}`);

        res.json({ message: 'OTP sent successfully', otp: otp });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset password with OTP
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { phone, otp, newPassword } = req.body;

        const user = await User.findOne({ 
            phone, 
            otp, 
            otpExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        // Hash new password
        const saltRounds = 10;
        user.password = await bcrypt.hash(newPassword, saltRounds);
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user data endpoint
app.get('/api/user/data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-password')
            .populate('team.level1', 'username email phone')
            .populate('team.level2', 'username email phone')
            .populate('team.level3', 'username email phone');

        res.json(user);
    } catch (error) {
        console.error('User data error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user bank info endpoint
app.post('/api/user/bank-info', authenticateToken, async (req, res) => {
    try {
        const { accountName, accountPhone, bankName } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                bankInfo: {
                    accountName,
                    accountPhone,
                    bankName
                }
            },
            { new: true }
        ).select('-password');
        
        res.json({ message: 'Bank information updated successfully', user });
    } catch (error) {
        console.error('Bank info update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create recharge request endpoint
app.post('/api/transactions/recharge', authenticateToken, async (req, res) => {
    try {
        const { amount, paymentMethod, transactionId } = req.body;
        
        const user = await User.findById(req.user._id);
        user.transactions.push({
            type: 'recharge',
            amount,
            paymentMethod,
            transactionId,
            status: 'pending'
        });
        
        await user.save();
        
        res.json({ message: 'Recharge request submitted successfully' });
    } catch (error) {
        console.error('Recharge error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create withdrawal request endpoint
app.post('/api/transactions/withdraw', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        
        const user = await User.findById(req.user._id);
        
        if (user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }
        
        user.balance -= amount;
        user.transactions.push({
            type: 'withdrawal',
            amount,
            status: 'pending'
        });
        
        await user.save();
        
        res.json({ message: 'Withdrawal request submitted successfully' });
    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get transactions endpoint
app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(user.transactions);
    } catch (error) {
        console.error('Transactions error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create investment endpoint
app.post('/api/investments', authenticateToken, async (req, res) => {
    try {
        const { planId, amount } = req.body;
        
        const user = await User.findById(req.user._id);
        
        if (user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }
        
        // Calculate end date based on plan
        const startDate = new Date();
        let endDate = new Date();
        let profitPercentage = 0;
        
        switch (planId) {
            case 1:
                endDate.setDate(startDate.getDate() + 5);
                profitPercentage = 0.02;
                break;
            case 2:
                endDate.setDate(startDate.getDate() + 10);
                profitPercentage = 0.05;
                break;
            case 3:
                endDate.setDate(startDate.getDate() + 12);
                profitPercentage = 0.18;
                break;
            case 4:
                endDate.setDate(startDate.getDate() + 20);
                profitPercentage = 0.24;
                break;
            case 5:
                endDate.setDate(startDate.getDate() + 30);
                profitPercentage = 0.45;
                break;
            default:
                return res.status(400).json({ message: 'Invalid plan ID' });
        }
        
        const expectedProfit = amount * profitPercentage;
        
        user.balance -= amount;
        user.investments.push({
            planId,
            amount,
            startDate,
            endDate,
            expectedProfit
        });
        
        await user.save();
        
        res.json({ message: 'Investment created successfully' });
    } catch (error) {
        console.error('Investment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get investments endpoint
app.get('/api/investments', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(user.investments);
    } catch (error) {
        console.error('Investments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Claim investment profit endpoint
app.post('/api/investments/:id/claim', authenticateToken, async (req, res) => {
    try {
        const investmentId = req.params.id;
        
        const user = await User.findById(req.user._id);
        const investment = user.investments.id(investmentId);
        
        if (!investment) {
            return res.status(404).json({ message: 'Investment not found' });
        }
        
        if (investment.status === 'completed') {
            return res.status(400).json({ message: 'Investment already completed' });
        }
        
        if (new Date() < investment.endDate) {
            return res.status(400).json({ message: 'Investment period not completed yet' });
        }
        
        const profit = investment.expectedProfit - investment.profitReceived;
        user.balance += profit;
        user.totalProfit += profit;
        investment.profitReceived = investment.expectedProfit;
        investment.status = 'completed';
        
        await user.save();
        
        res.json({ message: 'Profit claimed successfully', profit });
    } catch (error) {
        console.error('Claim investment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Purchase product endpoint
app.post('/api/products/purchase', authenticateToken, async (req, res) => {
    try {
        const { productId, name, cost, transactionId } = req.body;
        
        const user = await User.findById(req.user._id);
        
        if (user.balance < cost) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }
        
        user.balance -= cost;
        user.products.push({
            productId,
            name,
            cost,
            dailyEarningRate: 0.02432 // 2.432%
        });
        
        user.transactions.push({
            type: 'recharge',
            amount: cost,
            paymentMethod: 'product_purchase',
            transactionId,
            status: 'pending'
        });
        
        await user.save();
        
        res.json({ message: 'Product purchased successfully' });
    } catch (error) {
        console.error('Product purchase error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get products endpoint
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(user.products);
    } catch (error) {
        console.error('Products error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get affiliate data endpoint
app.get('/api/affiliate', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .populate('team.level1', 'username phone createdAt')
            .populate('team.level2', 'username phone createdAt')
            .populate('team.level3', 'username phone createdAt');
        
        const referralLink = `https://classic-maximize-pay.com/register?ref=${user._id}`;
        
        res.json({
            referralLink,
            team: user.team
        });
    } catch (error) {
        console.error('Affiliate data error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Complete daily task endpoint
app.post('/api/tasks/complete', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        
        // Add daily earnings (simplified)
        const dailyEarning = user.products.reduce((total, product) => {
            return total + (product.cost * product.dailyEarningRate);
        }, 0);
        
        user.dailyEarnings += dailyEarning;
        user.balance += dailyEarning;
        user.totalProfit += dailyEarning;
        
        await user.save();
        
        res.json({ message: 'Daily task completed successfully', earnings: dailyEarning });
    } catch (error) {
        console.error('Complete task error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get daily notification endpoint
app.get('/api/notification', async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const notification = await DailyNotification.findOne({
            date: { $gte: today }
        }).sort({ date: -1 });
        
        res.json(notification || { message: 'Welcome to CLASSIC-MAXIMIZE PAY!' });
    } catch (error) {
        console.error('Notification error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get daily task endpoint
app.get('/api/task', async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const task = await Task.findOne({
            date: { $gte: today }
        }).sort({ date: -1 });
        
        res.json(task || { message: 'Share your link with friends to earn more!' });
    } catch (error) {
        console.error('Task error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin endpoints

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find admin
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { adminId: admin._id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            admin: {
                id: admin._id,
                username: admin.username
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all users endpoint (admin)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all transactions endpoint (admin)
app.get('/api/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find().select('username transactions');
        
        const allTransactions = [];
        users.forEach(user => {
            user.transactions.forEach(transaction => {
                allTransactions.push({
                    _id: transaction._id,
                    userId: user._id,
                    username: user.username,
                    type: transaction.type,
                    amount: transaction.amount,
                    date: transaction.date,
                    status: transaction.status,
                    paymentMethod: transaction.paymentMethod,
                    transactionId: transaction.transactionId
                });
            });
        });
        
        res.json(allTransactions);
    } catch (error) {
        console.error('Admin transactions error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update transaction status endpoint (admin)
app.put('/api/admin/transactions/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const transactionId = req.params.id;
        
        // Find user with this transaction
        const user = await User.findOne({ 'transactions._id': transactionId });
        if (!user) {
            return res.status(404).json({ message: 'Transaction not found' });
        }
        
        // Update transaction status
        const transaction = user.transactions.id(transactionId);
        transaction.status = status;
        
        // If recharge is approved, add to balance
        if (status === 'approved' && transaction.type === 'recharge') {
            user.balance += transaction.amount;
        }
        
        await user.save();
        
        res.json({ message: 'Transaction status updated successfully' });
    } catch (error) {
        console.error('Transaction update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get dashboard stats endpoint (admin)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalInvested = await User.aggregate([
            { $unwind: '$investments' },
            { $group: { _id: null, total: { $sum: '$investments.amount' } } }
        ]);
        const totalWithdrawn = await User.aggregate([
            { $unwind: '$transactions' },
            { $match: { 'transactions.type': 'withdrawal', 'transactions.status': 'approved' } },
            { $group: { _id: null, total: { $sum: '$transactions.amount' } } }
        ]);
        
        const totalBalance = await User.aggregate([
            { $group: { _id: null, total: { $sum: '$balance' } } }
        ]);
        
        res.json({
            totalUsers,
            totalInvested: totalInvested[0]?.total || 0,
            totalWithdrawn: totalWithdrawn[0]?.total || 0,
            totalBalance: totalBalance[0]?.total || 0
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create daily notification endpoint (admin)
app.post('/api/admin/notification', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;
        
        const notification = new DailyNotification({
            message
        });
        
        await notification.save();
        
        res.json({ message: 'Notification created successfully' });
    } catch (error) {
        console.error('Create notification error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create daily task endpoint (admin)
app.post('/api/admin/task', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;
        
        const task = new Task({
            message
        });
        
        await task.save();
        
        res.json({ message: 'Task created successfully' });
    } catch (error) {
        console.error('Create task error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Process daily earnings (to be run by a cron job)
app.post('/api/admin/process-earnings', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({ 'products.status': 'active' });
        
        for (const user of users) {
            let dailyEarnings = 0;
            
            // Calculate earnings from products
            for (const product of user.products) {
                if (product.status === 'active') {
                    const earning = product.cost * product.dailyEarningRate;
                    dailyEarnings += earning;
                }
            }
            
            // Calculate earnings from investments
            for (const investment of user.investments) {
                if (investment.status === 'active') {
                    const days = Math.floor((new Date() - investment.startDate) / (1000 * 60 * 60 * 24));
                    const totalExpected = investment.amount * (investment.expectedProfit / investment.amount);
                    const dailyProfit = totalExpected / Math.floor((investment.endDate - investment.startDate) / (1000 * 60 * 60 * 24));
                    
                    if (investment.profitReceived + dailyProfit <= investment.expectedProfit) {
                        dailyEarnings += dailyProfit;
                        investment.profitReceived += dailyProfit;
                    } else if (investment.profitReceived < investment.expectedProfit) {
                        const remaining = investment.expectedProfit - investment.profitReceived;
                        dailyEarnings += remaining;
                        investment.profitReceived = investment.expectedProfit;
                        investment.status = 'completed';
                    }
                }
            }
            
            // Update user balance and earnings
            user.dailyEarnings = dailyEarnings;
            user.balance += dailyEarnings;
            user.totalProfit += dailyEarnings;
            
            await user.save();
        }
        
        res.json({ message: 'Daily earnings processed successfully' });
    } catch (error) {
        console.error('Process earnings error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Initialize admin user (run once)
app.post('/api/admin/init', async (req, res) => {
    try {
        const existingAdmin = await Admin.findOne();
        if (existingAdmin) {
            return res.status(400).json({ message: 'Admin already exists' });
        }
        
        const hashedPassword = await bcrypt.hash('admin123', 10);
        
        const admin = new Admin({
            username: 'admin',
            password: hashedPassword,
            email: 'admin@classic-maximize-pay.com'
        });
        
        await admin.save();
        
        res.json({ message: 'Admin user created successfully' });
    } catch (error) {
        console.error('Init admin error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Export app for testing
module.exports = app;