const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, required: true },
    time: { type: String, required: true },
    location: { type: String, required: true },
    capacity: { type: Number, required: true },
    registeredCount: { type: Number, default: 0 },
    status: { 
        type: String, 
        enum: ['Draft', 'Published', 'Completed', 'Cancelled'], 
        default: 'Draft' 
    },
    imageUrl: { type: String, default: '' }   // ✅ moved inside the schema
}, { timestamps: true });

module.exports = mongoose.model('Event', eventSchema);