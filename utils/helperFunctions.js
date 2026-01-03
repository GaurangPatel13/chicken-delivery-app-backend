export const validatePassword = (password) => {
    const uppercaseRegex = new RegExp("(?=.*[A-Z])");
    const lowercaseRegex = new RegExp("(?=.*[a-z])");
    const numericalRegex = new RegExp("(?=.*[0-9])");
    const specialCharacterRegex = new RegExp("(?=.*[!@#$%^&*])");
    const lengthRegex = new RegExp("^.{8,}$");

    return (
        uppercaseRegex.test(password) &&
        lowercaseRegex.test(password) &&
        numericalRegex.test(password) &&
        specialCharacterRegex.test(password) &&
        lengthRegex.test(password)
    );
};