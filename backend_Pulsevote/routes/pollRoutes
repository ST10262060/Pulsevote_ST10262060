const express = require("express");
const { protect } = require("../middleware/authMiddleware");
const { requireRole } = require("../middleware/roleMiddleware");
const {
    createPoll,
    votePoll,
    getPollResults,
    getOrgPolls,
    closePoll,
    openPoll
} = require("../controllers/pollController");

const router = express.Router();

router.post("/create-poll", protect, requireRole("manager"), createPoll);
router.post("/vote/:pollId", protect, requireRole("user"), votePoll);
router.get("/get-poll-results/:pollId", protect, getPollResults);
router.get("/get-polls/:organisationId", protect, getOrgPolls);
router.post("/close/:pollId", protect, requireRole("manager"), closePoll);
router.post("/open/:pollId", protect, requireRole("manager"), openPoll);

module.exports = router;