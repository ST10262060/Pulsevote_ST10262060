if (!email || !password) {
    setError("Email and password are required.");
    return;
    }

    if (!isValidEmail(email)) {
    setError("Invalid email format.");
    return;
    }

    if (!isStrongPassword(password)) {
    setError("Password must be at least 8 characters long and include letters and numbers.");
    return;
    }

    const isValidEmail = (email) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isStrongPassword = (password) =>
    /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/.test(password);
