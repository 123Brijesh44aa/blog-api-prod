import {BlogError} from "../utils/BlogError";

const generateAccessAndRefreshTokens = async (userId: string) => {
    try {

    } catch (error){
        console.log("Error generating access and refresh tokens");
        throw new BlogError("Internal Server Error", 500);
    }
}