import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.configDotenv();

const refresh_token_secret = process.env.REFRESH_TOKEN_SECRET;
const refresh_token_expiry = process.env.REFRESH_TOKEN_EXPIRY;

export const generateRefreshToken = (user) => {
    return jwt.sign(
        {
            id: user.id
        },
        refresh_token_secret,
        {
            expiresIn: refresh_token_expiry
        }
    )
}