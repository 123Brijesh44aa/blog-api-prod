import dotenv from "dotenv";
import { mailTransporter } from "../config/nodemailer.config.js";

dotenv.configDotenv();

const from = process.env.FROM;

const sendPasswordResetEmail = (user) => {

    const resetPasswordUrl = `http:localhost:3000/api/v2/blog/resetPassword/${user.resetToken}`;

    const mailOptions = {
        from: from,
        to: user.email,
        subject: "Password Reset",
        html: `<p>Click <a href="${resetPasswordUrl}">here</a> to reset your password.</p>`,
    }

    mailTransporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending password reset email : ", error);
            throw new BlogError("Error sending password reset email", 500);
        } else {
            console.log("Email sent : ", info.response);
        }
    });
}

export {sendPasswordResetEmail};