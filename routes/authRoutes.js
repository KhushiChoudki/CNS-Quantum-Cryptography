const express = require("express");
const router = express.Router();
const { signup, login, vpnConfig, getMetrics, simulateAttack, attackVisual } = require("../controllers/authController");

router.post("/signup", signup);
router.post("/login", login);
router.get("/vpn-config", vpnConfig);
router.get("/metrics", getMetrics);
router.post("/simulate-attack", simulateAttack);
router.post("/attack-visual", attackVisual);

module.exports = router;