require('dotenv').config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model.js");

const SECRET_KEY = process.env.JWT_SECRET_KEY;
const ALLOWED_ROLES = ["customer", "carrier", "driver", "admin"];

function signToken(user) {
    return jwt.sign(
        { userId: user._id.toString(), role: user.role },
        SECRET_KEY,
        { expiresIn: "7d" }
    );
}

function sanitize(userDoc) {
    const u = userDoc.toObject ? userDoc.toObject() : userDoc;
    delete u.password;
    return u;
}

async function register(req, res) {
    try {
        const body = req.body || {};
        const role = (body.role || "customer").toLowerCase();

        if (!ALLOWED_ROLES.includes(role)) {
            return res.status(400).json({ message: "Invalid role" });
        }

        const email = (body.email || "").toLowerCase().trim();
        const password = body.password;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const exists = await User.findOne({ email });
        if (exists) {
            return res.status(409).json({ message: "Email already registered" });
        }

        const hash = await bcrypt.hash(password, 10);

        // Map both B2C and B2B payloads safely
        const user = await User.create({
            email,
            password: hash,
            role,

            // B2C
            firstName: body.firstName || undefined,
            lastName: body.lastName || undefined,
            phone: body.phone || undefined,

            // B2B
            companyName: body.companyName || undefined,
            orgNumber: body.orgNumber || undefined,
            vatNumber: body.vatNumber || undefined,
            contactName: body.contactName || undefined,

            // Address
            address: body.address || undefined,
            zip: body.zip || undefined,
            city: body.city || undefined,
            country: body.country || undefined,
        });

        const token = signToken(user);
        return res.status(201).json({ message: "registered", token, user: sanitize(user) });
    } catch (err) {
        console.error("Register error:", err);
        return res.status(500).json({ message: "Server error" });
    }
}

async function login(req, res) {
    try {
        const email = (req.body.email || "").toLowerCase().trim();
        const password = req.body.password;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: "Invalid credentials" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ message: "Invalid credentials" });

        const token = signToken(user);
        return res.status(200).json({ message: "ok", token, user: sanitize(user) });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Server error" });
    }
}

async function me(req, res) {
    return res.status(200).json({ user: req.user });
}

module.exports = { register, login, me };
