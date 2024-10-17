import prismaClient from "../prismaClient.js";
import { sendVerificationEmail } from "../services/sendVerificationEmail.service.js";
import { BlogError } from "../utils/BlogError.js";
import { generateVerificationToken } from "../utils/verificationToken.util.js";



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



const resendVerificationEmail = async (req, res, next) => {
    try {
        const { email } = req.body;
        const user = await prismaClient.user.findUnique({
            where: { email: email },
        });
        if (!user) {
            return next(new BlogError("User does not exist for this email", 404));
        }

        if (user.isVerified) {
            return next(new BlogError("User is already verified", 400));
        }
        if (!user.isVerified) {
            if (user.verificationToken != null) {

                return next(new BlogError("Verification email already send , please check your email", 400));
            }
        }
        const verificationToken = generateVerificationToken(user.email);
        await prismaClient.user.update({
            where: { email: user.email },
            data: { verificationToken: verificationToken },
        });

        const updatedUserWithVerificationToken = await prismaClient.user.findUnique({
            where: { id: user.id },
        });
        sendVerificationEmail(updatedUserWithVerificationToken);
        res.status(200).json({
            message: "Verification email send successfully",
        });

    } catch (error) {
        next(error);
    }
}

export {verifyEmail, resendVerificationEmail };