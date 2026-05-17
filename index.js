const express = require("express");
const path = require("path");
const { connectDB } = require("./db");
const userRoutes = require("./routes/userRoutes");
const authRoutes = require("./routes/authRoutes");

const app = express();

app.use(express.json());

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

async function startServer() {
    try {
        // ✅ WAIT for MongoDB before anything else
        await connectDB();

        // Routes only after DB is ready
        app.use("/users", userRoutes);
        app.use("/auth", authRoutes);

        app.listen(3000, "0.0.0.0", () => {
            console.log("Server running on http://0.0.0.0:3000 🚀");
            console.log("Demo frontend → http://40.81.244.230:3000");
        });

    } catch (err) {
        console.error("Failed to start server:", err);
    }
}

startServer();