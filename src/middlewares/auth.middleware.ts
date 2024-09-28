import {Request, Response, NextFunction} from "express";
import {BlogError} from "../utils/BlogError";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import prismaClient from "../prismaClient";

dotenv.configDotenv();

export const verifyJWT = async (req: Request, res: Response, next: NextFunction) => {

    try {
        const access_token_secret = process.env.ACCESS_TOKEN_SECRET;
        if (!access_token_secret) {
            return next(new BlogError("ACCESS_TOKEN_SECRET is not defined in .env", 400))
        }

        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            return next(new BlogError("Unauthorized request", 401));
        }

        const decodedToken = jwt.verify(token, access_token_secret) as jwt.JwtPayload;

        const user = await prismaClient.user.findUnique({
            where: {id: decodedToken?.id},
        });

        if (!user) {
            // todo: NEXT_VIDEO: DISCUSS ABOUT FRONTEND
            return next(new BlogError("User not found", 404));
        }

        const {password: _, refreshToken: __, ...userWithoutSensitiveInfo} = user;

        req.user = userWithoutSensitiveInfo;

        next();
    } catch (error){
        next(new BlogError("Unauthorized request", 401));
    }

}