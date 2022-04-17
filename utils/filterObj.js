const filterObj = (...arg) => {
  const obj = {};
  // Remove properties from obj if not contained in arg
  Object.keys(arg[0]).forEach((element) => {
    if (arg.includes(element)) obj[element] = arg[0][element];
  });
  return obj;
};

module.exports = filterObj;
