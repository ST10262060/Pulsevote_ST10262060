const { validationResult } = require("express-validator");

const Organisation = require("../models/Organisation");
const User = require("../models/User");

exports.createOrganisation = async (req, res) => {
try {
    const { name } = req.body;

    const org = new Organisation({
    name,
    createdBy: req.user.id,
    members: [req.user.id]
    });

    const user = await User.findById(req.user.id);
    user.roles.push({ organisationId: org._id, role: "manager" });
    await user.save();

    org.generateJoinCode();
    await org.save();

    res.status(201).json({ message: "Organisation created", organisation: org });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.generateJoinCode = async (req, res) => {
try {
    const { organisationId } = req.params;
    const org = await Organisation.findById(organisationId);
    if (!org) return res.status(404).json({ message: "Organisation not found" });

    org.generateJoinCode();
    await org.save();

    res.json({ message: "Join code regenerated", joinCode: org.joinCode });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.joinOrganisation = async (req, res) => {
try {
    const { joinCode } = req.body;

    const org = await Organisation.findOne({ joinCode });
    if (!org) return res.status(404).json({ message: "Invalid join code" });

    if (!org.members.includes(req.user.id)) {
    org.members.push(req.user.id);
    await org.save();
    }

    const user = await User.findById(req.user.id);
    const alreadyInRole = user.roles.some(r => 
    r.organisationId?.toString() === org._id.toString()
    );

    if (!alreadyInRole) {
    user.roles.push({ organisationId: org._id, role: "user" });
    await user.save();
    }

    res.json({ message: "Joined organisation", organisation: org });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

const express = require("express");
const { protect } = require("../middleware/authMiddleware");
const { requireRole } = require("../middleware/roleMiddleware");
const {
createOrganisation,
generateJoinCode,
joinOrganisation
} = require("../controllers/organisationController");

const router = express.Router();

router.post("/create-organisation", protect, requireRole("manager"), createOrganisation);
router.post("/generate-join-code/:organisationId/", protect, requireRole("manager"), generateJoinCode);
router.post("/join-organisation", protect, joinOrganisation);

module.exports = router;