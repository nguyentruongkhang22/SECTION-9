module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  //   console.log(err.stack, 'con cac');
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
  });

  // Error.captureStackTrace(this, this.contructor);
};
