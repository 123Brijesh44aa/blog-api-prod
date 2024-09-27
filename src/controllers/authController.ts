import {NextFunction, Request, Response} from "express";
import {signupSchema} from "../validation/authValidation";
import {BlogError} from "../utils/BlogError";
import xss from "xss";
import prismaClient from "../prismaClient";
import bcrypt from "bcryptjs";
import {checkPassword} from "../utils/checkPassword.util";


const signupUser = async (req: Request, res: Response, next: NextFunction) => {

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


const loginUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        let {email, password} = req.body;
        if (!email){
            return next(new BlogError("email is required",400));
        }
        email = xss(email);
        const user = await prismaClient.user.findUnique({
            where: {email: email},
        });
        if (!user){
            return next(new BlogError("Invalid email or password", 401));
        }
        const isPasswordMatch = await checkPassword(password, user.password);
        if (!isPasswordMatch){
            return next(new BlogError("Invalid email or password", 401));
        }

    } catch (error){
        next(error);
    }
}

export {signupUser, loginUser};
