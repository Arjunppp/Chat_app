import mongoose  from "mongoose";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    role: {
        type: String,
        default: 'USER'
    },
    password: {
        type: String,
        required: true
    }
});

export const User = mongoose.model('User', userSchema);