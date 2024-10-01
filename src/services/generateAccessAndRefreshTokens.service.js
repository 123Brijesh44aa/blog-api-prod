import {BlogError} from "../utils/BlogError.js";
import prismaClient from "../prismaClient.js";
import {generateAccessToken} from "./generateAccessToken.service.js";
import {generateRefreshToken} from "./generateRefreshToken.service.js";

export const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await prismaClient.user.findUnique({
            where: {id: userId},
        });
        if (!user){
            throw new BlogError("User not found", 404);
        }
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // save refresh token in the database
        await prismaClient.user.update({
            where: { id: user.id},
            data: { refreshToken: refreshToken },
        });

        return {accessToken,refreshToken};
    } catch (error){
        console.log("Error generating access and refresh tokens");
        throw new BlogError("Internal Server Error", 500);
    }
}