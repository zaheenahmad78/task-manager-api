const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect('mongodb+srv://user_database:data1234@cluster0.5dbyrvw.mongodb.net/testdb')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ Error:', err));

// ==================== USER SCHEMA ====================
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// ==================== TASK SCHEMA ====================
const taskSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['pending', 'in-progress', 'completed'], default: 'pending' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});
const Task = mongoose.model('Task', taskSchema);

// ==================== AUTH MIDDLEWARE ====================
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, 'mykey');
        req.userId = decoded.id;
        next();
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// ==================== ADMIN MIDDLEWARE ====================
const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.userId);
        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ success: false, message: 'Admin access required' });
        }
    } catch (error) {
        res.status(403).json({ success: false, message: 'Admin access required' });
    }
};

// ==================== REGISTER API ====================
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashed = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashed, role: role || 'user' });
        await user.save();
        const token = jwt.sign({ id: user._id }, 'mykey');
        res.json({ success: true, message: 'Registered', token, user: { name, email, role: user.role } });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// ==================== LOGIN API ====================
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.json({ success: false, message: 'User not found' });
        
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ success: false, message: 'Wrong password' });
        
        const token = jwt.sign({ id: user._id }, 'mykey');
        res.json({ success: true, message: 'Login Success', token, user: { name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// ==================== TASKS CRUD APIs ====================

// CREATE Task
app.post('/tasks', authMiddleware, async (req, res) => {
    try {
        const { title, description, status } = req.body;
        const task = new Task({ title, description, status, userId: req.userId });
        await task.save();
        res.json({ success: true, message: 'Task created', task });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// READ all tasks (for logged in user)
app.get('/tasks', authMiddleware, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.userId }).sort({ createdAt: -1 });
        res.json({ success: true, tasks });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// UPDATE task
app.put('/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id, userId: req.userId });
        if (!task) {
            return res.status(404).json({ success: false, message: 'Task not found' });
        }
        const { title, description, status } = req.body;
        if (title) task.title = title;
        if (description) task.description = description;
        if (status) task.status = status;
        await task.save();
        res.json({ success: true, message: 'Task updated', task });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// DELETE task
app.delete('/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!task) {
            return res.status(404).json({ success: false, message: 'Task not found' });
        }
        res.json({ success: true, message: 'Task deleted' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ADMIN APIs ====================

// Get all users (only admin)
app.get('/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    const users = await User.find().select('-password');
    res.json({ success: true, users });
});

// Get all tasks (only admin)
app.get('/admin/tasks', authMiddleware, adminMiddleware, async (req, res) => {
    const tasks = await Task.find().populate('userId', 'name email');
    res.json({ success: true, tasks });
});

// ==================== HOME API ====================
app.get('/', (req, res) => {
    res.json({ 
        message: 'Task Manager API is running',
        endpoints: [
            'POST /register',
            'POST /login',
            'GET /tasks',
            'POST /tasks',
            'PUT /tasks/:id',
            'DELETE /tasks/:id',
            'GET /admin/users',
            'GET /admin/tasks'
        ]
    });
});

// ==================== START SERVER ====================
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));