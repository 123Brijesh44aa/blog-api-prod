import {BlogError} from "../utils/BlogError";
import prismaClient from "../prismaClient";
import {generateAccessToken} from "./generateAccessToken.service";
import {generateRefreshToken} from "./generateRefreshToken.service";

export const generateAccessAndRefreshTokens = async (userId: string) => {
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