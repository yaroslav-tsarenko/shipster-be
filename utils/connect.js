const mongoose = require("mongoose");

async function connectDB(uri) {
    if (!uri) throw new Error("MONGO_URI is missing");
    if (mongoose.connection.readyState >= 1) return;

    mongoose.set("strictQuery", true);
    await mongoose.connect(uri, {
        autoIndex: true,
    });
    console.log("✅ Mongo connected");
}

module.exports = connectDB;
