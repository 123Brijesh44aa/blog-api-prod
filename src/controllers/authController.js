import { signupSchema } from "../validation/authValidation.js";
import { BlogError } from "../utils/BlogError.js";
import xss from "xss";
import prismaClient from "../prismaClient.js";
import bcrypt from "bcryptjs";
import { checkPassword } from "../utils/checkPassword.util.js";
import { generateAccessAndRefreshTokens } from "../services/generateAccessAndRefreshTokens.service.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { generateVerificationToken } from "../utils/verificationToken.util.js";
import { sendVerificationEmail } from "../services/sendVerificationEmail.service.js";


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
        let { name, email, password } = req.body;

        if (
            [name, email, password].some((field) => field?.trim() === "")
        ) {
            return next(new BlogError("All fields are required", 400));
        }

        // Data Sanitization against XSS
        name = xss(name);
        email = xss(email);

        // Data Validation using Joi
        const { error } = signupSchema.validate(req.body);
        if (error) return next(new BlogError(error.details[0].message, 400));

        // Check if user already exist
        const user = await prismaClient.user.findUnique({
            where: { email: email },
        });
        if (user) {
            // if user already exists and not verified
            if (!user.isVerified) {
                // check if user VerificationToken is not null
                if (user.verificationToken != null) {
                    try {
                        // check if existing verification token is still valid
                        jwt.verify(user.verificationToken, process.env.EMAIL_VERIFICATION_TOKEN_SECRET)
                        // if token is still valid, inform user
                        return res.status(200).json({
                            message: "A verification email has already been sent. Please check your email inbox."
                        });
                    } catch (error) {
                        if (error.name == "TokenExpiredError") {
                            // if the token has expired , generate a new one
                            const verificationToken = generateVerificationToken(user.email);
                            // save token to User record
                            await prismaClient.user.update({
                                where: { id: user.id },
                                data: { verificationToken: verificationToken }
                            });
                            // Resend Verification Email 
                            const updatedUserWithVerificationToken = await prismaClient.user.findUnique({
                                where: { id: user.id },
                            });
                            sendVerificationEmail(updatedUserWithVerificationToken);

                            return res.status(200).json({
                                message: 'The previous verification link has expired. A new verification email has been sent.'
                            });
                        }
                        // Handle other errors related to token verification
                        return res.status(500).json({ message: 'Something went wrong with the verification process.' });
                    }
                }
            }
            return next(new BlogError("User with this email already exists", 400));
        }

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
        const { password: _, refreshToken: __, ...userWithoutSensitiveInfo } = newUser;

        const createdUser = await prismaClient.user.findUnique({
            where: { id: newUser.id },
        });

        // Check if user Created or not
        if (!createdUser) {
            return next(new BlogError("Something went wrong while registering the User", 500));
        }

        // Generate JWT Email Verification Token
        const verificationToken = generateVerificationToken(newUser.email);

        // save token to User record
        await prismaClient.user.update({
            where: { id: newUser.id },
            data: { verificationToken: verificationToken }
        });

        // Send Verification Email
        const updatedUserWithVerificationToken = await prismaClient.user.findUnique({
            where: { id: newUser.id },
        })
        sendVerificationEmail(updatedUserWithVerificationToken);

        return res.status(201).json(
            {
                message: "We have sent you an email to verify your account. Please check your email.",
                user: userWithoutSensitiveInfo,
            }
        );

    } catch (error) {
        next(error);
    }
}


const loginUser = async (req, res, next) => {
    try {
        let { email, password } = req.body;
        if (!email) {
            return next(new BlogError("email is required", 400));
        }
        email = xss(email);
        const user = await prismaClient.user.findUnique({
            where: { email: email },
        });
        if (!user) {
            return next(new BlogError("Invalid email or password", 401));
        }
        const isPasswordMatch = await checkPassword(password, user.password);
        if (!isPasswordMatch) {
            return next(new BlogError("Invalid email or password", 401));
        }


        // check if email is verified or not
        if (!user.isVerified) {
            return next(new BlogError("Please verify your email to login", 401));
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user.id);

        // here we are fetching the user from the database again to remove the password and refreshToken from the response, but now you will ask that we already have the user object in the user variable, so why we are fetching it again from the database? the reason is that the user object does not have the password and refreshToken fields because the user object contains the previous reference of the user object which was fetched from the database, so we need to fetch the user object again from the database to get the updated user object which contains the password and refreshToken fields.
        const loggedInUser = await prismaClient.user.findUnique({
            where: { id: user.id },
        });

        // remove password and refreshToken from loggedInUser
        let loggedInUserWithoutSensitiveInfo;
        if (loggedInUser) {
            const { password: _, refreshToken: __, ...info } = loggedInUser;
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
            where: { id: user.id },
            data: { refreshToken: null },
        });

        const options = {
            httpOnly: true,
            secure: true,
        }

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json({ message: "User logged out successfully" });

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
            where: { id: decodedToken?.id },
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

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user.id);

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



const verifyEmail = async (req, res, next) => {
    try {
        const token = req.params.token;
        const decoded = jwt.verify(token, process.env.EMAIL_VERIFICATION_TOKEN_SECRET);
        const email = decoded.email;

        // find the user using email and token . 
        const user = await prismaClient.user.findFirst({
            where: {
                email: email,
                verificationToken: token
            }
        });
        if (!user) {
            return next(new BlogError("The verification link is invalid or has expired. Please request a new verification email.", 404));
        }
        // check if token expired or not 
        const currentTime = Date.now() / 1000;
        if (decoded.exp < currentTime) {
            return next(new BlogError("The verification link is invalid or has expired. Please request a new verification email.", 404));
        }
        // update the user record to remove the verification token and set the emailVerified field to true
        await prismaClient.user.update({
            where: { id: user.id },
            data: {
                verificationToken: null,
                isVerified: true
            }
        });

        // Send a success response
        res.status(200).json(
            {
                message: "Email verified successfully. You can now log in.",
            }
        )


    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return next(new BlogError("The verification link is invalid or has expired. Please request a new verification email.", 404));
        }
        next(error);
    }
}


export { signupUser, loginUser, logoutUser, refreshAccessToken, verifyEmail };
