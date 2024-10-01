import {signupSchema} from "../validation/authValidation.js";
import {BlogError} from "../utils/BlogError.js";
import xss from "xss";
import prismaClient from "../prismaClient.js";
import bcrypt from "bcryptjs";
import {checkPassword} from "../utils/checkPassword.util.js";
import {generateAccessAndRefreshTokens} from "../services/generateAccessAndRefreshTokens.service.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";


dotenv.configDotenv();

const signupUser = async (req, res, next) => {

    /**
     * get user details from request
     * validation - not empty
     * Data Sanitization against XSS
     * check if user is already exists: username, email
     * check for images, check for avatar
     * upload them to cloudinary, avatar
     * hash the password
     * create user object - create entry in db
     * remove password and refresh token field from response
     * check for user creation
     * return res
     */

    try {
        let {name, email, password} = req.body;

        if (
            [name, email, password].some((field) => field?.trim() === "")
        ) {
            return next(new BlogError("All fields are required", 400));
        }

        // Data Sanitization against XSS
        name = xss(name);
        email = xss(email);

        // Data Validation using Joi
        const {error} = signupSchema.validate(req.body);
        if (error) return next(new BlogError(error.details[0].message, 400));

        // Check if user already exist
        const user = await prismaClient.user.findUnique({
            where: {email: email},
        });
        if (user) return next(new BlogError("User with this email already exists", 400));

        // Hash the password using bcryptjs
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new User
        const newUser = await prismaClient.user.create({
            data: {
                name: name,
                email: email,
                password: hashedPassword
            }
        });

        // Remove password and refreshToken from the newly created User
        const {password: _, refreshToken: __, ...userWithoutSensitiveInfo} = newUser;

        const createdUser = await prismaClient.user.findUnique({
            where: {id: newUser.id},
        });

        // Check if user Created or not
        if (!createdUser) {
            return next(new BlogError("Something went wrong while registering the User", 500));
        }

        return res.status(201).json(
            {
                message: "User created successfully",
                user: userWithoutSensitiveInfo,
            }
        );

    } catch (error) {
        next(error);
    }
}


const loginUser = async (req, res, next) => {
    try {
        let {email, password} = req.body;
        if (!email) {
            return next(new BlogError("email is required", 400));
        }
        email = xss(email);
        const user = await prismaClient.user.findUnique({
            where: {email: email},
        });
        if (!user) {
            return next(new BlogError("Invalid email or password", 401));
        }
        const isPasswordMatch = await checkPassword(password, user.password);
        if (!isPasswordMatch) {
            return next(new BlogError("Invalid email or password", 401));
        }
        const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user.id);

        // here we are fetching the user from the database again to remove the password and refreshToken from the response, but now you will ask that we already have the user object in the user variable, so why we are fetching it again from the database? the reason is that the user object does not have the password and refreshToken fields because the user object contains the previous reference of the user object which was fetched from the database, so we need to fetch the user object again from the database to get the updated user object which contains the password and refreshToken fields.
        const loggedInUser = await prismaClient.user.findUnique({
            where: {id: user.id},
        });

        // remove password and refreshToken from loggedInUser
        let loggedInUserWithoutSensitiveInfo;
        if (loggedInUser) {
            const {password: _, refreshToken: __, ...info} = loggedInUser;
            loggedInUserWithoutSensitiveInfo = info;
        }

        // send loggedInUserWithoutSensitiveInfo with cookies
        const options = {
            httpOnly: true,
            secure: true,
        }

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                {
                    message: "User logged in Successfully",
                    user: loggedInUserWithoutSensitiveInfo,
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                }
            )

    } catch (error) {
        next(error);
    }
}


const logoutUser = async (req, res, next) => {
    try {
        const user = req.user;
        if (!user) {
            return next(new BlogError("User not found", 404));
        }

        await prismaClient.user.update({
            where: {id: user.id},
            data: {refreshToken: null},
        });

        const options = {
            httpOnly: true,
            secure: true,
        }

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json({message: "User logged out successfully"});

    } catch (error) {
        next(error);
    }
}


const refreshAccessToken = async (req, res, next) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) {
            return next(new BlogError("Unauthorized request", 401));
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await prismaClient.user.findUnique({
            where: {id: decodedToken?.id},
        });

        if (!user) {
            return next(new BlogError("Invalid Refresh Token", 404));
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            return next(new BlogError("Refresh token is expired or used", 401));
        }

        const options = {
            httpOnly: true,
            secure: true
        };

        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user.id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                {
                    message: "Access token refreshed",
                    accessToken: accessToken,
                    refreshToken: newRefreshToken,
                }
            )
    } catch (error) {
        next(error);
    }

}
export {signupUser, loginUser, logoutUser, refreshAccessToken};
