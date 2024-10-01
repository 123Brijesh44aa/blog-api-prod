import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.configDotenv();


const access_token_secret = process.env.ACCESS_TOKEN_SECRET;
const access_token_expiry = process.env.ACCESS_TOKEN_EXPIRY;

if (!access_token_secret || !access_token_expiry) {
    throw new Error("ACCESS_TOKEN_SECRET or ACCESS TOKEN EXPIRY is not defined in .env");
}

export const generateAccessToken = (user) => {
    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
        },
        access_token_secret,
        {expiresIn: access_token_expiry}
    )
}