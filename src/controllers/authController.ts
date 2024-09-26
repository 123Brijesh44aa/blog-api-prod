import {NextFunction, Request, Response} from "express";
import {signupSchema} from "../validation/authValidation";
import {BlogError} from "../utils/BlogError";
import xss from "xss";
import prismaClient from "../prismaClient";
import bcrypt from "bcryptjs";


const signupUser = async (req: Request,res: Response, next: NextFunction) => {

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

        // Data Sanitization against XSS
        req.body.name = xss(req.body.name);
        req.body.email = xss(req.body.email);

        // Data Validation using Joi
        const {error} = signupSchema.validate(req.body);
        if (error) return next(new BlogError(error.details[0].message, 400));

        // Check if user already exist
        const {name,email,password} = req.body;
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

        // Check if user Created or not
        if (newUser){
            return res.status(201).json(
                {
                    message: "User created successfully",
                    newUser: newUser,
                    user: {
                        id: newUser.id,
                        name: newUser.name,
                        email: newUser.email,
                    },
                }
            );
        } else {
            return next(new BlogError("User creation failed", 500));
        }

    } catch (error){
        next(error);
    }

}

export {signupUser};
