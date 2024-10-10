import crypto from "crypto";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.configDotenv();


const generateVerificationToken = (userEmail) => {
    return jwt.sign(
        { email: userEmail },
        process.env.EMAIL_VERIFICATION_TOKEN_SECRET,
        { expiresIn: process.env.EMAIL_VERIFICATION_TOKEN_EXPIRY }
    )
    
}

export { generateVerificationToken };

// console.log(generateVerificationToken());
