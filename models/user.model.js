const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
    {
        email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        password: { type: String, required: true },
        role: { type: String, enum: ["customer", "carrier", "driver", "admin"], default: "customer" },
        name: { type: String },
        secondName: { type: String },
        phone: { type: String },
        companyName: { type: String },
        orgNumber: { type: String },
        vatNumber: { type: String },
        contactName: { type: String },
        address: { type: String },
        zip: { type: String },
        city: { type: String },
        country: { type: String },
        avatar: { type: String },
        notifications: {
            notificationsEnabled: { type: Boolean, default: false },
            aiNotifications: { type: Boolean, default: false },
            carrierNotifications: { type: Boolean, default: false },
            loadNotifications: { type: Boolean, default: false },
            driverNotifications: { type: Boolean, default: false },
            updateNotifications: { type: Boolean, default: false },
        },
    },
    { timestamps: true }
);

const User = mongoose.models.User || mongoose.model("User", UserSchema);

module.exports = User;
