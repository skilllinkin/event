const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

// Secure Data Model Blueprint Schemas
const User = require('./models/User');
const Event = require('./models/event');
const Registration = require('./models/Registration');

const app = express();

const allowList = ['http://localhost:5000'];
const renderOrigin = /^https:\/\/([a-z0-9-]+\.)*onrender\.com$/i;

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowList.includes(origin) || renderOrigin.test(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS origin not allowed'));
        }
    },
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const isValidObjectId = (value) => typeof value === 'string' && /^[a-f\d]{24}$/i.test(value);
const isNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0;
const validStatuses = ['Draft', 'Published', 'Completed', 'Cancelled'];

function validateEventPayload({ title, description, date, time, location, capacity, status }, { partial = false } = {}) {
    const requiredFields = { title, description, date, time, location, capacity };
    for (const [field, value] of Object.entries(requiredFields)) {
        if ((!partial || value !== undefined) && (value === undefined || value === null || (typeof value === 'string' && value.trim() === ''))) {
            return field.charAt(0).toUpperCase() + field.slice(1) + ' is required';
        }
    }
    if (date !== undefined && (typeof date !== 'string' || Number.isNaN(new Date(date).getTime()))) return 'Date must be valid';
    if (capacity !== undefined && (!Number.isInteger(Number(capacity)) || Number(capacity) < 1)) return 'Capacity must be at least 1';
    if (status !== undefined && !validStatuses.includes(status)) return 'Status must be Draft, Published, Completed, or Cancelled';
    return null;
}

// Main Database Node Connection
if (!process.env.MONGO_URI) {
    console.error('❌ Missing MONGO_URI in environment variables.');
} else {
    mongoose.connect(process.env.MONGO_URI)
        .then(() => console.log('🛡️ Securely connected to MongoDB Atlas System Network!'))
        .catch((err) => console.error('Database connection system error:', err));
}

// ========================================================
// SECURITY INTERCEPTOR MIDDLEWARE (FR-03)
// ========================================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access Denied: Missing operational session token' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
        if (err) {
            return res.status(403).json({ error: 'Session expired or token validation signature failed' });
        }
        req.user = decodedUser;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({
                error: `Access Forbidden: Requires administrative privileges (${role})`
            });
        }
        next();
    };
};

// ========================================================
// MODULE 01: USER IDENTIFICATION ENGINE (FR-01, FR-02)
// ========================================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!isNonEmptyString(name)) return res.status(400).json({ error: 'Name is required' });
        if (!isNonEmptyString(email)) return res.status(400).json({ error: 'Email is required' });
        if (!/^\S+@\S+\.\S+$/.test(email.trim())) return res.status(400).json({ error: 'Email must be valid' });
        if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.status(400).json({ error: 'An account with this email is already registered.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const assignedRole = 'attendee';

        const newUser = new User({
            name: name.trim(),
            email: normalizedEmail,
            password: hashedPassword,
            role: assignedRole
        });
        await newUser.save();

        res.status(201).json({ message: 'Account constructed successfully!' });
    } catch (err) {
        res.status(500).json({
            error: 'System identity creation crash fault',
            details: err.message
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid identification credentials provided.' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid identification credentials provided.' });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );
        res.status(200).json({
            message: 'Authorization cleared',
            token,
            role: user.role,
            name: user.name
        });
    } catch (err) {
        res.status(500).json({ error: 'Identity processing gate server fault' });
    }
});

// ========================================================
// ADMIN-ONLY LOGIN GATE (Strict Role Enforcement)
// ========================================================
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid administrator credentials.' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid administrator credentials.' });
        }

        // 🛡️ CRITICAL: Refuse to issue a token unless the DB role is exactly "admin"
        if (user.role !== 'admin') {
            return res.status(403).json({
                error: 'Access denied. This account does not have administrator privileges.'
            });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.status(200).json({
            message: 'Administrator authorization cleared',
            token,
            role: user.role,
            name: user.name
        });
    } catch (err) {
        res.status(500).json({ error: 'Administrator identity gate failure.' });
    }
});

// ========================================================
// MODULE 02: ADMIN LIFECYCLE MANAGEMENT
// ========================================================

app.post('/api/admin/events', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const { title, description, date, time, location, capacity, status, imageUrl } = req.body;
        const validationError = validateEventPayload({ title, description, date, time, location, capacity, status: status || 'Draft' });
        if (validationError) return res.status(400).json({ error: validationError });

        const parsedCapacity = parseInt(capacity, 10);
        if (isNaN(parsedCapacity) || parsedCapacity <= 0) {
            return res.status(400).json({
                error: 'Capacity parameters must balance as a positive whole number.'
            });
        }

        const newEvent = new Event({
            title,
            description,
            date,
            time,
            location,
            capacity: parsedCapacity,
            status: status || 'Draft',
            imageUrl: imageUrl ? imageUrl.trim() : ''
        });
        await newEvent.save();
        res.status(201).json({ message: 'Event successfully logged.', event: newEvent });
    } catch (err) {
        res.status(500).json({ error: 'Lifecycle save failure' });
    }
});

app.put('/api/admin/events/:id', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const { title, description, date, time, location, capacity, status, imageUrl } = req.body;
        const validationError = validateEventPayload({ title, description, date, time, location, capacity, status });
        if (validationError) return res.status(400).json({ error: validationError });
        const event = await Event.findById(req.params.id);
        if (!event) {
            return res.status(404).json({ error: 'Target event instance missing.' });
        }

        // Section 08 Constraint Check: Validate Capacity Changes against Active Signups
        if (capacity !== undefined) {
            const parsedCapacity = parseInt(capacity, 10);
            if (isNaN(parsedCapacity) || parsedCapacity <= 0) {
                return res.status(400).json({
                    error: 'Capacity parameters must balance as a positive whole number.'
                });
            }

            // Count real active registrations inside database dynamically
            const activeCount = await Registration.countDocuments({
                eventId: req.params.id,
                status: 'Active'
            });
            if (parsedCapacity < activeCount) {
                return res.status(400).json({
                    error: `Business Rule Violation: Capacity cannot be set lower than the current ${activeCount} active registrations.`
                });
            }
            event.capacity = parsedCapacity;
        }

        event.title = title !== undefined ? title : event.title;
        event.description = description !== undefined ? description : event.description;
        event.date = date !== undefined ? date : event.date;
        event.time = time !== undefined ? time : event.time;
        event.location = location !== undefined ? location : event.location;
        event.status = status !== undefined ? status : event.status;
        event.imageUrl = imageUrl !== undefined ? imageUrl.trim() : event.imageUrl;

        await event.save();
        res.status(200).json({ message: 'Event operational parameters updated.', event });
    } catch (err) {
        res.status(500).json({ error: 'Lifecycle update save failure' });
    }
});

app.delete('/api/admin/events/:id', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const event = await Event.findByIdAndDelete(req.params.id);
        if (!event) {
            return res.status(404).json({ error: 'Target event instance missing.' });
        }
        await Registration.deleteMany({ eventId: req.params.id });
        res.status(200).json({ message: 'Event and associated registrations purged successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Lifecycle deletion fault' });
    }
});

app.get('/api/admin/events', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const events = await Event.find().sort({ date: 1 });
        res.status(200).json(events);
    } catch (err) {
        res.status(500).json({ error: 'Admin event feed pull fault.' });
    }
});

app.get('/api/admin/events/:id/roster', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const roster = await Registration
            .find({ eventId: req.params.id, status: 'Active' })
            .populate('userId', 'name email');
        res.status(200).json(roster);
    } catch (err) {
        res.status(500).json({ error: 'Manifest collection pipeline fault.' });
    }
});

app.get('/api/admin/dashboard/metrics', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const totalEvents = await Event.countDocuments();
        const metrics = await Event.aggregate([
            {
                $group: {
                    _id: null,
                    totalSeats: { $sum: '$capacity' },
                    totalBooked: { $sum: '$registeredCount' }
                }
            }
        ]);

        const summary = metrics[0] || { totalSeats: 0, totalBooked: 0 };
        res.status(200).json({
            eventsCount: totalEvents,
            capacityTotal: summary.totalSeats,
            reservationsTotal: summary.totalBooked,
            availableCapacity: summary.totalSeats - summary.totalBooked
        });
    } catch (err) {
        res.status(500).json({ error: 'Analytics compilation fault' });
    }
});

// ========================================================
// MODULE 03: GUEST DISCOVERY & TICKETING SYSTEM
// ========================================================

app.get('/api/events', async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const feed = await Event.find({
            status: 'Published',
            date: { $gte: today }
        });
        res.status(200).json(feed);
    } catch (err) {
        res.status(500).json({ error: 'Discovery data pull fault.' });
    }
});

app.post('/api/events/register', authenticateToken, requireRole('attendee'), async (req, res) => {
    try {
        const { eventId } = req.body;
        const userId = req.user.id;

        if (!isValidObjectId(eventId)) return res.status(400).json({ error: 'Event ID is invalid.' });

        const event = await Event.findById(eventId);
        if (!event) {
            return res.status(404).json({
                error: 'Target operational event instance does not exist.'
            });
        }

        // Business Rule: Must be Published
        if (event.status !== 'Published') {
            return res.status(400).json({
                error: 'Registration rejected: Event is closed or un-published.'
            });
        }

        // Business Rule: Event must not be in the past (day-boundary comparison)
        const targetDate = new Date(event.date);
        const currentSystemDate = new Date();

        const targetDayStr = targetDate.toISOString().split('T')[0];
        const currentDayStr = currentSystemDate.toISOString().split('T')[0];

        if (targetDayStr < currentDayStr) {
            return res.status(400).json({
                error: 'Registration rejected: This event timeline is in the past.'
            });
        }

        // Duplicate check happens before the atomic seat claim.
        const activeRegistration = await Registration.findOne({ eventId, userId, status: 'Active' });
        if (activeRegistration) {
            return res.status(400).json({ error: 'Duplicate entry blocked: You hold an active ticket allocation for this event.' });
        }

        const updated = await Event.findOneAndUpdate(
            { _id: eventId, $expr: { $lt: ['$registeredCount', '$capacity'] } },
            { $inc: { registeredCount: 1 } },
            { new: true }
        );
        if (!updated) return res.status(400).json({ error: 'Capacity full' });

        try {
            let ticket = await Registration.findOne({ eventId, userId });
            if (ticket) {
                ticket.status = 'Active';
                await ticket.save();
            } else {
                ticket = await Registration.create({ eventId, userId, status: 'Active' });
            }
            return res.status(201).json({ message: 'Ticket reserved successfully! Allocation complete.', ticket });
        } catch (registrationError) {
            // Return the claimed seat if the registration write did not complete.
            await Event.findByIdAndUpdate(eventId, { $inc: { registeredCount: -1 } });
            if (registrationError && registrationError.code === 11000) {
                return res.status(400).json({ error: 'Duplicate entry blocked: You hold an active ticket allocation for this event.' });
            }
            throw registrationError;
        }

    } catch (err) {
        res.status(500).json({
            error: 'Ticketing process database fault.',
            details: err.message
        });
    }
});

app.get('/api/events/my-registrations', authenticateToken, requireRole('attendee'), async (req, res) => {
    try {
        const bookings = await Registration
            .find({ userId: req.user.id, status: 'Active' })
            .populate('eventId');
        res.status(200).json(bookings);
    } catch (err) {
        res.status(500).json({ error: 'Personal itinerary fetch fault.' });
    }
});

app.post('/api/events/cancel', authenticateToken, requireRole('attendee'), async (req, res) => {
    try {
        const { registrationId } = req.body;

        if (!isValidObjectId(registrationId)) return res.status(400).json({ error: 'Registration ID is invalid.' });

        const ticket = await Registration.findOne({
            _id: registrationId,
            userId: req.user.id,
            status: 'Active'
        });

        if (!ticket) {
            return res.status(404).json({
                error: 'No active matching reservation ownership found.'
            });
        }

        ticket.status = 'Cancelled';
        await ticket.save();

        await Event.findByIdAndUpdate(ticket.eventId, {
            $inc: { registeredCount: -1 }
        });

        res.status(200).json({
            message: 'Registration successfully released. Seat open.'
        });
    } catch (err) {
        res.status(500).json({ error: 'Cancellation drop execution error.' });
    }
});

// ========================================================
// START SERVER
// ========================================================
// ========================================================
// FIRST-BOOT ADMIN SEED (Idempotent — safe to run every start)
// ========================================================
async function seedDefaultAdmin() {
    const adminEmail    = process.env.DEFAULT_ADMIN_EMAIL;
    const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;

    if (!adminEmail || !adminPassword) {
        console.log('ℹ️  No default admin configured (DEFAULT_ADMIN_EMAIL/PASSWORD not set).');
        return;
    }

    try {
        const existing = await User.findOne({ email: adminEmail });
        if (existing) {
            if (existing.role !== 'admin') {
                existing.role = 'admin';
                await existing.save();
                console.log('🛡️  Promoted existing user to admin:', adminEmail);
            } else {
                console.log('🛡️  Admin account already exists:', adminEmail);
            }
            return;
        }

        const salt = await bcrypt.genSalt(10);
        const hashed = await bcrypt.hash(adminPassword, salt);

        await User.create({
            name: 'System Administrator',
            email: adminEmail,
            password: hashed,
            role: 'admin'
        });
        console.log('🛡️  Seeded initial admin account:', adminEmail);
    } catch (err) {
        console.error('Admin seed error:', err.message);
    }
}

// Kick off seeds once MongoDB is connected
async function seedDevelopmentData() {
    if (process.env.NODE_ENV === 'production') return;

    try {
        const demoEmail = 'demo@nowshera.com';
        if (!await User.findOne({ email: demoEmail })) {
            await User.create({
                name: 'Demo Attendee', email: demoEmail,
                password: await bcrypt.hash('demo123', 10), role: 'attendee'
            });
            console.log('Seeded demo attendee account.');
        }

        const title = 'Welcome to Nowshera Events';
        if (!await Event.findOne({ title })) {
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            tomorrow.setHours(0, 0, 0, 0);
            await Event.create({
                title,
                description: 'A sample published event for exploring the reservation flow.',
                date: tomorrow, time: '10:00 AM', location: 'Nowshera Community Hall',
                capacity: 50, status: 'Published'
            });
            console.log('Seeded sample event.');
        }
    } catch (err) {
        console.error('Development seed error:', err.message);
    }
}

mongoose.connection.once('open', async () => {
    await seedDefaultAdmin();
    await seedDevelopmentData();
});

app.listen(process.env.PORT || 5000, () => console.log(`🚀 Nowshera Core Engine online on port ${process.env.PORT || 5000}`));





