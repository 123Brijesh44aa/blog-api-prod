import prismaClient from "../prismaClient.js";
import { sendVerificationEmail } from "../services/sendVerificationEmail.service.js";
import { BlogError } from "../utils/BlogError.js";
import { generateVerificationToken } from "../utils/verificationToken.util.js";

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

export { resendVerificationEmail };