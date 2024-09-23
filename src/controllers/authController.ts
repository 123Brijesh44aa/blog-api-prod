import { Request, Response} from "express";

const signupUser = async (req: Request,res: Response) => {
    // get user details from request
    // validation - not empty
    // Data Sanitization against XSS
    // check if user is already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    try {
        const {name,email,password} = req.body;
        return  res.status(200).json(
            {
                user: {
                    name,
                    email,
                    password,
                }
            }
        )
    } catch (e){
        console.log(e);
    }

}

export {signupUser};