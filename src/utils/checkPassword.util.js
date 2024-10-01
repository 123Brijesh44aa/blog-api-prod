import bcrypt from "bcryptjs";
import {BlogError} from "./BlogError.js";

export const checkPassword = async (inputPassword, storedPassword) => {
    try {
        return await bcrypt.compare(inputPassword, storedPassword);
    } catch (error){
        console.log("Error while checking password");
        throw new BlogError("Internal Server Error", 500);
    }
}