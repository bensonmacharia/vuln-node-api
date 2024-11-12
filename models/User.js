const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    uid: {
        type: Number,
        unique: true,
    },
    firstname: {
        type: String,
        required: true
    },
    lastname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    isadmin: {
        type: Number,
        required: true,
        default: 0
    },
});

// Pre-save hook to implement auto-incremental ID
UserSchema.pre("save", async function (next) {
    if (this.isNew) {
        const count = await mongoose.model("User").countDocuments();  // Get the current count of users
        this.uid = count + 1;  // Set the auto-incremental ID

        // Set isadmin to 1 if uid is 1
        if (this.uid === 1) {
            this.isadmin = 1;
        }
    }
    next();
});

module.exports = mongoose.model("User", UserSchema);
