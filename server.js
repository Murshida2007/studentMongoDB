
const express = require("express");
const { MongoClient } = require("mongodb");
const fs = require("fs");
const path = require("path");
const EventEmitter = require("events");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000;

// MongoDB connection
const url = "mongodb://127.0.0.1:27017";
const client = new MongoClient(url);

const dbName = "nodeLab";
let users;

// Create custom event emitter
const userEvents = new EventEmitter();

// Create audit log
const logFile = path.join(__dirname, "audit.log");

// Listen for signup and login events
userEvents.on("signup", (name, email) => {
    const message =
        `${new Date().toLocaleString()} - SIGNUP: ${name} (${email})\n`;

    fs.appendFileSync(logFile, message);
    console.log("Signup event recorded");
});

userEvents.on("login", (name, email) => {
    const message =
        `${new Date().toLocaleString()} - LOGIN: ${name} (${email})\n`;

    fs.appendFileSync(logFile, message);
    console.log("Login event recorded");
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Connect to MongoDB and start the server
async function startServer() {
    try {
        await client.connect();

        console.log("Connected to MongoDB!");

        const db = client.db(dbName);
        users = db.collection("users");

        // Ensure email addresses are unique
        await users.createIndex({ email: 1 }, { unique: true });

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("MongoDB connection failed:", error.message);
        process.exit(1);
    }
}

// SIGN UP
app.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            !name.trim() ||
            !email.trim() ||
            password.length < 6
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter valid details. Password must be at least 6 characters."
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        // Check whether email already exists
        const existingUser = await users.findOne({
            email: cleanEmail
        });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "Email already registered. Please log in."
            });
        }

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user in MongoDB
        await users.insertOne({
            name: cleanName,
            email: cleanEmail,
            password: hashedPassword
        });

        // Trigger signup event
        userEvents.emit("signup", cleanName, cleanEmail);

        res.status(201).json({
            success: true,
            message: "Registration successful! Please log in."
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "Email already registered."
            });
        }

        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error during registration."
        });
    }
});

// LOG IN
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message: "Please enter email and password."
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // Find the user in MongoDB
        const user = await users.findOne({
            email: cleanEmail
        });

        // Check password
        if (
            !user ||
            !(await bcrypt.compare(password, user.password))
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        // Trigger login event
        userEvents.emit("login", user.name, user.email);

        res.json({
            success: true,
            message: "Login successful!",
            name: user.name,
            email: user.email
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error during login."
        });
    }
});

// Start the application
startServer();
