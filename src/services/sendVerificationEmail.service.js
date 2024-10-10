import { mailTransporter } from "../config/nodemailer.config.js";
import dotenv from "dotenv";
import { BlogError } from "../utils/BlogError.js";

dotenv.configDotenv();

const from = process.env.FROM;

const sendVerificationEmail = (user) => {
    const verificationUrl = `http://localhost:3000/api/v2/blog/verifyEmail/${user.verificationToken}`;
    const mailOptions = {
        from: from,
        to: user.email,
        subject: "Email Verification",
        html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email.</p>`,
    }

    mailTransporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending verification email : ", error);
            throw new BlogError("Error sending verification email", 500);
        } else {
            console.log("Email sent : ", info.response);
        }
    });
};

export { sendVerificationEmail };



// sendVerificationEmail({email: "oddsworld0121@gmail.com", verificationToken: "hello-this-is-brijesh"});




