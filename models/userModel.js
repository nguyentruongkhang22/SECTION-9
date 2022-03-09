const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please tell us your name!'],
    },
    email: {
        type: String,
        required: [true, 'Email address is needed!'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email!'],
    },
    photo: {
        type: String,
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        select: false,
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password!'],
        validate: function (el) {
            return el === this.password;
        },
    },
    passwordChangedAt: Date,
});

userSchema.pre('save', async function (next) {
    // IF THE PASSWORD IS MODIFIED
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12);

    this.passwordConfirm = undefined;
    next();
});

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt / 1000, 10);

        console.log(changedTimestamp, JWTTimestamp);
        return JWTTimestamp > changedTimestamp;
    }
    return false;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
