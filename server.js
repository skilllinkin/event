const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Secure Data Model Blueprint Schemas
const User = require('./models/User');
const Event = require('./models/event');
const Registration = require('./models/registration');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

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
        const { name, email, password, role } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'An account with this email is already registered.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const assignedRole = 'attendee'; // Everyone starts as an attendee

        const newUser = new User({
            name,
            email,
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
// MODULE 02: ADMIN LIFECYCLE MANAGEMENT
// ========================================================

app.post('/api/admin/events', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const { title, description, date, time, location, capacity, status } = req.body;

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
            status: status || 'Draft'
        });
        await newEvent.save();
        res.status(201).json({ message: 'Event successfully logged.', event: newEvent });
    } catch (err) {
        res.status(500).json({ error: 'Lifecycle save failure' });
    }
});

app.put('/api/admin/events/:id', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const { title, description, date, time, location, capacity, status } = req.body;
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

app.post('/api/events/register', authenticateToken, async (req, res) => {
    try {
        const { eventId } = req.body;
        const userId = req.user.id;

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

        // Business Rule: Capacity check
        if (event.registeredCount >= event.capacity) {
            return res.status(400).json({
                error: 'Registration rejected: Seating capacity threshold completely full!'
            });
        }

        // Business Rule: Prevent duplicate active registrations
        const activeRegistration = await Registration.findOne({
            eventId,
            userId,
            status: 'Active'
        });
        if (activeRegistration) {
            return res.status(400).json({
                error: 'Duplicate entry blocked: You hold an active ticket allocation for this event.'
            });
        }

        // Update existing cancelled ticket or create a fresh one
        let ticket = await Registration.findOne({ eventId, userId });
        if (ticket) {
            ticket.status = 'Active';
        } else {
            ticket = new Registration({ eventId, userId, status: 'Active' });
        }
        await ticket.save();

        event.registeredCount += 1;
        await event.save();

        res.status(201).json({
            message: 'Ticket reserved successfully! Allocation complete.',
            ticket
        });

    } catch (err) {
        res.status(500).json({
            error: 'Ticketing process database fault.',
            details: err.message
        });
    }
});

app.get('/api/events/my-registrations', authenticateToken, async (req, res) => {
    try {
        const bookings = await Registration
            .find({ userId: req.user.id, status: 'Active' })
            .populate('eventId');
        res.status(200).json(bookings);
    } catch (err) {
        res.status(500).json({ error: 'Personal itinerary fetch fault.' });
    }
});

app.post('/api/events/cancel', authenticateToken, async (req, res) => {
    try {
        const { registrationId } = req.body;

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
app.listen(PORT, () => console.log(`🚀 Nowshera Core Engine online on port ${PORT}`));