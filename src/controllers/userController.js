const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const dotenv = require('dotenv');
dotenv.config();

exports.registerUser = (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;
    bcrypt.hash(password, 10, async (err, hashedPassword) => {
        if (err) return res.status(500).json({ error: 'Internal Server Error' });
        try {
            const user = await User.create({
                firstName,
                lastName,
                email,
                password: hashedPassword,
                role,
                is_verified: false,
            });
            res.status(201).json({ message: 'User registered successfully!', user });
        } catch (error) {
            console.error('Error creating user:', error); 
            res.status(500).json({ error: 'Database Error', details: error.message });
        }
    });
};


exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'You are not authorized to access this page' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' } 
        );
        res.json({
            message: 'Login successful',
            token, 
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};
exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);  
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            message: 'User profile',
            user: {
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

