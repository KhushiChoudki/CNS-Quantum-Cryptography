const express = require("express");
const path = require("path");
const { connectDB } = require("./db");
const userRoutes = require("./routes/userRoutes");
const authRoutes = require("./routes/authRoutes");

const app = express();
app.use(express.json());

// Serve demo frontend
app.use(express.static(path.join(__dirname, "public")));

// Connect to DB
connectDB();

// Routes
app.use("/users", userRoutes);
app.use("/auth", authRoutes);

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000 🚀");
    console.log("Demo frontend → http://localhost:3000");
});