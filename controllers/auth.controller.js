require('dotenv').config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model.js");

const ALLOWED_ROLES = ["customer", "carrier", "driver", "admin"];
const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET_KEY;
const REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET_KEY;
const DASHBOARD_URL = process.env.DASHBOARD_URL;

function createAccessToken(user) {
    return jwt.sign({ userId: user._id, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}
function createRefreshToken(user) {
    return jwt.sign({ userId: user._id }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}
function sanitize(userDoc) {
    const u = userDoc.toObject ? userDoc.toObject() : userDoc;
    delete u.password;
    return u;
}

function cookieOpts(req) {
    const isLocal =
        req.hostname === "localhost" ||
        req.hostname.startsWith("127.") ||
        req.hostname.endsWith(".local");

    return {
        access: {
            httpOnly: false,
            secure: !isLocal,
            sameSite: isLocal ? "Lax" : "None",
            domain: isLocal ? undefined : ".shipster.se",
            path: "/",
            maxAge: 15 * 60 * 1000,
        },
        refresh: {
            httpOnly: true,
            secure: !isLocal,
            sameSite: isLocal ? "Lax" : "None",
            domain: isLocal ? undefined : ".shipster.se",
            path: "/",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        },
    };
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

        const user = await User.create({
            email,
            password: hash,
            role,
            firstName: body.firstName || undefined,
            lastName: body.lastName || undefined,
            phone: body.phone || undefined,
            companyName: body.companyName || undefined,
            orgNumber: body.orgNumber || undefined,
            vatNumber: body.vatNumber || undefined,
            name: body.name || undefined,
            secondName: body.secondName || undefined,
            address: body.address || undefined,
            zip: body.zip || undefined,
            city: body.city || undefined,
            country: body.country || undefined,
        });

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);

        const isLocalhost = req.hostname === 'localhost' || req.hostname.startsWith('127.');

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: !isLocalhost,
            sameSite: isLocalhost ? 'Lax' : 'None',
            domain: isLocalhost ? undefined : '.shipster.se',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.cookie('token', accessToken, {
            httpOnly: false,
            secure: !isLocalhost,
            sameSite: isLocalhost ? 'Lax' : 'None',
            domain: isLocalhost ? undefined : '.shipster.se',
            maxAge: 15 * 60 * 1000
        });

        res.status(201).json({ message: "registered", user: sanitize(user), redirectUrl: DASHBOARD_URL });
    } catch (err) {
        console.error("Register error:", err);
        return res.status(500).json({ message: "Server error" });
    }
}

async function login(req, res) {
    try {
        const email = (req.body.email || "").toLowerCase().trim();
        const password = req.body.password || "";

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const user = await User.findOne({ email }).select("+password");
        if (!user || !user.password) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ message: "Invalid credentials" });

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        const opts = cookieOpts(req);

        res.cookie("refreshToken", refreshToken, opts.refresh);
        res.cookie("token", accessToken, opts.access);

        return res
            .status(200)
            .json({ message: "ok", accessToken, user: sanitize(user), redirectUrl: DASHBOARD_URL });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Server error" });
    }
}


async function refresh(req, res) {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: 'No refresh token' });

    try {
        const payload = jwt.verify(token, REFRESH_TOKEN_SECRET);
        const user = await User.findById(payload.userId);
        if (!user) return res.status(401).json({ message: 'User not found' });

        const accessToken = createAccessToken(user);
        res.cookie('token', accessToken, {
            httpOnly: false,
            secure: true,
            sameSite: 'None',
            domain: req.hostname.includes('shipster.se') ? '.shipster.se' : undefined,
            maxAge: 15 * 60 * 1000
        });
        res.json({ accessToken });
    } catch (err) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
}

function logout(req, res) {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        domain: req.hostname.includes('shipster.se') ? '.shipster.se' : undefined
    });
    res.clearCookie('token', {
        httpOnly: false,
        secure: true,
        sameSite: 'none',
        domain: req.hostname.includes('shipster.se') ? '.shipster.se' : undefined
    });
    res.json({ message: 'Logged out' });
}

async function me(req, res) {
    return res.status(200).json({ user: sanitize(req.user) });
}

module.exports = {
    register,
    login,
    refresh,
    logout,
    me
};

