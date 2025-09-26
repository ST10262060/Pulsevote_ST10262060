exports.register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(400).json({ message: "Invalid input", errors: errors.array() });

        // rest of your logic
}