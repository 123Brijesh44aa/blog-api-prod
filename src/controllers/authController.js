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
import { generatePasswordResetToken } from "../utils/passwordResetToken.util.js";
import { sendPasswordResetEmail } from "../services/sendPasswordResetEmail.service.js";


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

        // update the lastLogin field
        await prismaClient.user.update({
            where: { id: user.id },
            data: { lastLogin: new Date() }
        });

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





const forgetPassword = async (req, res, next) => {
    try {
        const { email } = req.body;
        const user = await prismaClient.user.findUnique({
            where: { email: email },
        });
        if (!user) {
            return next(new BlogError("User with this email does not exist", 404));
        }
        const passwordResetToken = generatePasswordResetToken(user.email);
        // update user with resetToken
        await prismaClient.user.update({
            where: { email: user.email },
            data: { resetToken: passwordResetToken },
        });
        const updatedUserWithResetToken = await prismaClient.user.findUnique({
            where: { id: user.id },
        });
        // send password reset email with reset token
        sendPasswordResetEmail(updatedUserWithResetToken);
        res.status(200).json({
            message: "A password reset email has been sent to your email address."
        });
    } catch (error) {
        next(error);
    }
}


const resetPassword = async (req, res, next) => {
    try {
        const token = req.params.token;
        const { password, confirmPassword } = req.body;
        if (token === null || token === undefined) {
            return next(new BlogError("Invalid password reset link", 404));
        }
        if (!password || !confirmPassword) {
            return next(new BlogError("Password and Confirm Password are required", 400));
        }
        if (password !== confirmPassword) {
            return next(new BlogError("Password and Confirm Password do not match", 400));
        }
        // verify the resetToken
        const decoded = jwt.verify(token, process.env.PASSWORD_RESET_TOKEN_SECRET);
        const email = decoded.email;
        // find the user using email and resetToken
        const user = await prismaClient.user.findFirst({
            where: {
                email: email,
                resetToken: token,
            },
        });
        if (!user || user.resetToken !== token) {
            return next(new BlogError("The password reset link is invalid or has expired. Please request a new password reset email.", 404));
        }
        // hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // update the user password and resetToken
        await prismaClient.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                resetToken: null,
            },
        });
        // send a success response
        res.status(200).json({
            message: "Password reset successfully. You can now Login with your new password.",
        });
    } catch (error) {
        // handle token expired error
        if (error.name === "TokenExpiredError"){
            return next(new BlogError("The password reset link is invalid or has expired. Please request a new password reset email.", 404));
        }
        next(error);
    }
}


export { signupUser, loginUser, logoutUser, refreshAccessToken, forgetPassword , resetPassword};
