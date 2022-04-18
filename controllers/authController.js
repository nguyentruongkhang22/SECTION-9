const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const bcryptjs = require('bcryptjs');

const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const User = require('../models/userModel');
const sendEmail = require('../utils/email');

const signToken = (id) => {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 60 * 60 * 24 * 1000,
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token);

  // Hide password from output without changing it on database
  user.password = undefined;
  res.status(200).json({
    status: 'success',
    token: token,
    data: {
      user,
    },
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

  createSendToken(newUser, 201, res);
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

  // If everything is ok, send token back to client
  createSendToken(user, 201, res);
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

  console.log(decoded);
  // Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) return next(new AppError('This token no longer exist', 401));

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
    if (!roles.includes(req.user.role))
      return next(new AppError("You don't have permission to perform this action"), 403);
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  try {
    // Find the user according to email
    const user = await User.findOne({ email: req.body.email });

    // Check if user exists
    if (!user) return next(new AppError('There is no user with the given email', 404));

    // Create reset password token and save it to database
    const resetToken = user.createPasswordResetToken();

    await user.save({ validateBeforeSave: false });

    // Send token to user through email
    const resetURL = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password submit your PATCH request your new password and passwordConfirm to: ${resetURL}.`;

    sendEmail({
      email: user.email,
      subject: 'Reset password',
      message: message,
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to your email!',
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new AppError('Something is wrong, please try again later!', 500));
  }
});

exports.resetPassword = async (req, res, next) => {
  try {
    // Get the user based on token
    const hashedToken = await crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    // If token is not expired and user exists then reset the password
    if (!user) {
      next(new AppError('Token is expired or the user does not exist!'), 500);
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Change the passwordChangedAt property
    user.passwordChangedAt = Date.now();

    await user.save({ validateBeforeSave: false });
    // Login and send JWT
    createSendToken(user, 200, res);
  } catch (error) {
    console.log(error);
  }
};

exports.updatePassword = catchAsync(async (req, res, next) => {
  const { email, currentPassword, passwordConfirm } = req.body;

  // Get user
  const user = await User.findById(req.user.id).select('+password');
  // Check if post current password is correct
  if (!(await user.correctPassword(currentPassword, user.password))) {
    return next(new AppError('Your input password is not correct!'), 401);
  }
  // Update password
  user.password = password;
  user.passwordConfirm = passwordConfirm;

  await user.save();
  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });

  // Login, send JWT token
  createSendToken(user, 200, res);
});
