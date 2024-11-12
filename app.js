const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

// Connect to MongoDB
// mongoose.connect(process.env.MONGO_URI)
//     .then(() => console.log("MongoDB connected"))
//     .catch((err) => console.error(err));

const connectWithRetry = () => {
    console.log('MongoDB connection with retry');
    mongoose.connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    }).then(() => {
        console.log('MongoDB is connected');
    }).catch(err => {
        console.log('MongoDB connection unsuccessful, retry after 5 seconds.', err);
        setTimeout(connectWithRetry, 5000);
    });
};

connectWithRetry();

// Middleware to validate JWT
const auth = (req, res, next) => {
    const token = req.header("Authorization").split(" ")[1];
    if (!token) return res.status(401).json({ msg: "No token, authorization denied" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_WEAK_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).json({ msg: "Token is not valid" });
    }
};

// Register Route
app.post("/register", async (req, res) => {
    const { firstname, lastname, email, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ msg: "User already exists" });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
        firstname,
        lastname,
        email,
        password: hashedPassword,
    });

    await newUser.save();
    res.json({ msg: "User registered successfully" });
});

// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid email or password" });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid email or password" });

    // Generate JWT token
    const token = jwt.sign({ id: user._id, uid: user.uid, isadmin: user.isadmin }, process.env.JWT_WEAK_SECRET, { expiresIn: "1h" });
    res.json({ msg: "Successful login", token: token });
});

// View User Profile Route
app.get("/user/profile", auth, async (req, res) => {
    //const user = await User.findById(req.user.id).select("-password");
    const user = await User.findOne({ uid: req.user.uid }).select("-password");
    res.json(user);
});

// View All users Route
app.get("/users", auth, async (req, res) => {
    // Find the user by the ID from the decoded token
    const user = await User.findById(req.user.id);
    if (user.isadmin != 1) return res.status(403).json({ msg: "Only administrators are allowed to query all users data!" });
    const users = await User.find().select("-password");
    res.json(users);
});

app.get("/user/profile", auth, async (req, res) => {
    //const user = await User.findById(req.user.id).select("-password");
    const user = await User.findOne({ uid: req.user.uid }).select("-password");
    res.json(user);
});

// Insecure User Profile Edit Route
app.put('/profile/edit/:uid', auth, async (req, res) => {
    try {
        const { firstname, lastname, email } = req.body;

        // Find user by ID from URL parameter
        const user = await User.findOneAndUpdate(
            { uid: req.params.uid },
            { firstname, lastname, email },
            { new: true, runValidators: true }
        );
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Return the updated user's profile (excluding password)
        updatedUser = { id: user._id, "uid": user.uid, "firstname": user.firstname, "lastname": user.lastname, "email": user.email }

        res.json({ user: updatedUser, msg: "User updated successfully" });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Secure User Profile Edit Route
app.put('/user/profile/edit', auth, async (req, res) => {
    try {
        const { firstname, lastname, email } = req.body;

        // Find user by _id and update the fields if they exist in the request body
        // _id is taken from the JWT token that is submitted with the req
        const user = await User.findOneAndUpdate(
            { uid: req.user.uid },
            { firstname, lastname, email },
            { new: true, runValidators: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Return the updated user's profile (excluding password)
        updatedUser = { id: user._id, "uid": user.uid, "firstname": user.firstname, "lastname": user.lastname, "email": user.email }

        res.json({ user: updatedUser, msg: "User updated successfully" });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Insecure Password reset Route
app.put('/password/reset/:uid', auth, async (req, res) => {
    try {
        const { newPassword } = req.body;

        if (!newPassword) return res.status(400).json({ msg: "New password is required" });

        // Find user by ID from URL parameter
        const user = await User.findOne({ uid: req.params.uid });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        updatedUser = { "uid": user.uid, "firstname": user.firstname, "lastname": user.lastname, "email": user.email }

        res.json({ user: updatedUser, msg: "Password has been reset successfully" });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Secure Password Reset Route
app.put("/user/password/reset", auth, async (req, res) => {
    const { newPassword } = req.body;

    if (!newPassword) return res.status(400).json({ msg: "New password is required" });

    try {
        // Find the user by the ID from the decoded token
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: "User not found" });

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        updatedUser = { "uid": user.uid, "firstname": user.firstname, "lastname": user.lastname, "email": user.email }

        res.json({ user: updatedUser, msg: "Password has been reset successfully" });
    } catch (err) {
        res.status(500).json({ msg: "Server error" });
    }
});

// Start the server
const PORT = process.env.PORT || 8008;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));