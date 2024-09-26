import {PrismaClientKnownRequestError} from "prisma/prisma-client/runtime/library";
import {NextFunction, Request, Response} from "express";
import {BlogError} from "../utils/BlogError";

// Prisma specific error handling
const handlePrismaError = (error: PrismaClientKnownRequestError) => {
    let message;

    if (error.code === "P2002"){
        message = `Duplicate value for field: ${error.meta?.target}. Please choose another value.`;
        return new BlogError(message, 400);
    }
    return new BlogError("Database operation failed", 500);
};

export const errorHandlerMiddleware = (error: any, req: Request, res: Response, next: NextFunction) => {
    // Prisma Errors
    if (error instanceof PrismaClientKnownRequestError){
        error = handlePrismaError(error);
    }

    // Check if the error is operational ( expected )
    if (error.isOperational){
        return res.status(error.statusCode).json(
            {
                status: error.status,
                message: error.message
            }
        );
    }

    // Unknown or programming error ( don't expose details in production )
    console.error("ERROR 💥:", error);
    return res.status(500).json(
        {
            status: "error",
            message: "Something went wrong!",
        }
    );
}