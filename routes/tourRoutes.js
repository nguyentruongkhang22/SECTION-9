const express = require('express');

const { protect, restrictTo } = require('../controllers/authController');

const tourController = require('./../controllers/tourController');

const router = express.Router();

// router.param('id', tourController.checkID);

router.route('/top-5-cheap').get(tourController.aliasTopTours, tourController.getAllTours);

router.route('/tour-stats').get(tourController.getTourStats);
router.route('/monthly-plan/:year').get(tourController.getMonthlyPlan);

router.route('/').get(protect, tourController.getAllTours).post(tourController.createTour);

router
  .route('/:id')
  .get(tourController.getTour)
  .patch(tourController.updateTour)
  .delete(protect, restrictTo('admin'), tourController.deleteTour);

module.exports = router;
