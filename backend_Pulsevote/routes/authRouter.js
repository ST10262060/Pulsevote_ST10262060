const { body } = require("express-validator");

const router = express.Router(); // this is already there

const emailValidator = body("email")
.isEmail().withMessage("Email must be valid")
.normalizeEmail();

const passwordValidator = body("password")
.isLength({ min: 8 }).withMessage("Password must be at least 8 characters")
.matches(/[A-Za-z]/).withMessage("Password must include a letter")
.matches(/\d/).withMessage("Password must include a number")
.trim().escape();

router.post("/register", [emailValidator, passwordValidator], register);
router.post("/login", [emailValidator, body("password").notEmpty().trim().escape()], login);