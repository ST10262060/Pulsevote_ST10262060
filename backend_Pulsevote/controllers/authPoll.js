const Poll = require("../models/Poll");
const Organisation = require("../models/Organisation");
const User = require("../models/User")

exports.createPoll = async (req, res) => {
try {
    const { organisationId, question, options } = req.body;

    if (!options || options.length < 2) {
    return res.status(400).json({ message: "A poll must have at least two options" });
    }

    const org = await Organisation.findById(organisationId);
    if (!org) return res.status(404).json({ message: "Organisation not found" });

    const poll = await Poll.create({
    organisationId,
    question,
    options,
    createdBy: req.user.id
    });

    res.status(201).json({ message: "Poll created", poll });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.votePoll = async (req, res) => {
try {
    const { pollId } = req.params;
    const { optionIndex } = req.body;

    const poll = await Poll.findById(pollId);
    if (!poll) return res.status(404).json({ message: "Poll not found" });
    if (poll.status !== "open") return res.status(400).json({ message: "Poll is closed" });

    const alreadyVoted = poll.votes.some(v => v.userId.toString() === req.user.id);
    if (alreadyVoted) {
    return res.status(409).json({ message: "You have already voted" });
    }

    poll.votes.push({ userId: req.user.id, optionIndex });
    await poll.save();

    res.json({ message: "Vote recorded", poll });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.getPollResults = async (req, res) => {
try {
    const { pollId } = req.params;

    const poll = await Poll.findById(pollId).lean();
    if (!poll) return res.status(404).json({ message: "Poll not found" });

    const user = await User.findById(req.user.id).lean();
    const isAdmin = user?.roles?.some(r => r.role === "admin");
    const isMember = user?.roles?.some(
    r => r.organisationId?.toString() === poll.organisationId.toString()
    );
    if (!isAdmin && !isMember) {
    return res.status(403).json({ message: "Not a member of this organisation" });
    }

    const optionCount = poll.options.length;
    const counts = Array(optionCount).fill(0);

    for (const v of (poll.votes || [])) {
    if (typeof v.optionIndex === "number" && v.optionIndex >= 0 && v.optionIndex < optionCount) {
        counts[v.optionIndex]++;
    }
    }

    const totalVotes = counts.reduce((a, b) => a + b, 0);
    const percentages = counts.map(c => (totalVotes ? +( (c / totalVotes) * 100 ).toFixed(2) : 0));

    let userVoteIndex = null;
    if (poll.votes?.length) {
    const mine = poll.votes.find(v => v.userId?.toString() === req.user.id);
    if (mine) userVoteIndex = mine.optionIndex;
    }

    return res.json({
    poll: {
        _id: poll._id,
        organisationId: poll.organisationId,
        question: poll.question,
        options: poll.options,
        status: poll.status
    },
    results: {
        counts,
        percentages,
        totalVotes,
        userVoteIndex
    }
    });
} catch (err) {
    return res.status(500).json({ error: "Server error"});
}
};

exports.getOrgPolls = async (req, res) => {
try {
    const { organisationId } = req.params;
    const polls = await Poll.find({ organisationId });
    res.json(polls);
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.closePoll = async (req, res) => {
try {
    const {pollId } = req.params;
    
    const poll = await Poll.findById(pollId);
    if (!poll) return res.status(404).json({ message: "Poll not found" });

    poll.status = "closed";
    await poll.save();

    res.json({ message: "Poll closed", poll });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};

exports.openPoll = async (req, res) => {
try {
    const {pollId } = req.params;
    
    const poll = await Poll.findById(pollId);
    if (!poll) return res.status(404).json({ message: "Poll not found" });

    poll.status = "open";
    await poll.save();

    res.json({ message: "Poll opened", poll });
} catch (err) {
    res.status(500).json({ error: "Server error" });
}
};