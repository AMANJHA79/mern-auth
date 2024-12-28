const express = require('express');
const router = express.Router();
const { getUserdata } = require('../controllers/user-controller');
const userAuth = require('../middleware/user-auth');

router.get('/userdata', userAuth, getUserdata);

module.exports = router;