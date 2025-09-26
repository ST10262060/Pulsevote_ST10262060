const mongoose = require("mongoose");

const voteSchema = new mongoose.Schema({
userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
optionIndex: { type: Number, required: true }
}, { _id: false });

const pollSchema = new mongoose.Schema({
organisationId: { type: mongoose.Schema.Types.ObjectId, ref: "Organisation", required: true },
question: { type: String, required: true },
options: [{ type: String, required: true }],
createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
status: { type: String, enum: ["open", "closed"], default: "open" },
votes: [voteSchema]
});

pollSchema.index({ organisationId: 1 });

module.exports = mongoose.model("Poll", pollSchema);