const express = require("express");
const { register, login, me } = require("../controllers/auth.controller");
const basicAuth = require("../middleware/basicAuth.middleware.js");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/me", basicAuth, me);

module.exports = router;
