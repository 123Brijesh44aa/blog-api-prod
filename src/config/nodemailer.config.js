
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.configDotenv();


const userEmail = process.env.EMAIL;
const userPassword = process.env.PASSWORD;


const mailTransporter = nodemailer.createTransport(
    {
        service: "Gmail",
        auth: {
            user: userEmail,
            pass: userPassword,
        }
    }
);

export {mailTransporter};