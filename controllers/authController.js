const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const User = require('../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');

const signToken = (id) => {
    return jwt.sign({ id: id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        role: req.body.role,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        passwordChangedAt: req.body.passwordChangedAt,
    });

    const token = signToken(newUser._id);

    res.status(200).json({
        status: 'success',
        token: token,
        data: {
            user: newUser,
        },
    });
});

exports.login = catchAsync(async function (req, res, next) {
    const { email, password } = req.body;

    // Check if email and password are exist
    if (!email || !password) {
        return next(new AppError('Please provide email and password', 400));
    }

    // Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError('Incorrect Password or Email', 401));
    }

    console.log(user);
    // If everything is ok, send token back to client
    const token = signToken(user._id);

    res.status(200).json({
        status: 'success',
        token: token,
    });
});

exports.protect = catchAsync(async (req, res, next) => {
    let token;
    // Getting token and check if it's there
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    // console.log(token);
    if (!token) {
        next(new AppError('You are not logged in please log in to get access.', 401));
    }
    // Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) next(new AppError('This token no longer exist', 401));

    // Check if user changed password after token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(new AppError('Password changed recently, please try again', 401));
    }

    // Access granted
    req.user = currentUser;
    next();
});

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        console.log(Object.entries(req));
        if (!roles.includes(req.user.role))
            return next(new AppError("You don't have permission to perfom this action"), 403);
        next();
    };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });

    if (!user) return next(new AppError('There is no user with the given email', 404));

    const resetToken = User.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
});
exports.resetPassword = (req, res, next) => {};
