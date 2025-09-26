const { registerLimiter, loginLimiter} = require("../middleware/rateLimiter")

router.post("/register-user", registerLimiter, [emailValidator, passwordValidator], registerUser);
router.post("/register-manager", protect, requireRole("admin"), registerLimiter, [emailValidator, passwordValidator], registerManager);
router.post("/register-admin", registerLimiter, [emailValidator, passwordValidator], registerAdmin);

router.post("/login", loginLimiter, [emailValidator, body("password").notEmpty().trim().escape()], login);

