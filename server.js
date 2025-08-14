require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const connectDB = require("./utils/connect");

const authRoute = require("./routes/auth.route");

const app = express();

app.use(cors({ origin: process.env.CORS_ORIGIN || true, credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

app.get("/health", (_req, res) => res.status(200).json({ ok: true }));
app.use("/auth", authRoute);

// 404
app.use((req, res) => res.status(404).json({ message: "Not found" }));

const PORT = process.env.PORT || 4000;

connectDB(process.env.MONGODB_URI)
    .then(() => {
        app.listen(PORT, () => console.log(`🚀 API on http://localhost:${PORT}`));
    })
    .catch((err) => {
        console.error("Mongo connect failed:", err);
        process.exit(1);
    });
