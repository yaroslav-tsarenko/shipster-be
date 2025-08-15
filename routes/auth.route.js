const express = require("express");
const { register, login, refresh, logout, me } = require("../controllers/auth.controller.js");
const basicAuth = require("../middleware/basicAuth.middleware.js");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/me", basicAuth, me);

module.exports = router;
