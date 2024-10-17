import jwt from "jsonwebtoken";
import dotenv from "dotenv";


dotenv.configDotenv();


const generatePasswordResetToken = (userEmail) => {
    return jwt.sign(
        {email: userEmail},
        process.env.PASSWORD_RESET_TOKEN_SECRET,
        {expiresIn: process.env.PASSWORD_RESET_TOKEN_EXPIRY}
    );
}


export {generatePasswordResetToken};