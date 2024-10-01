import prismaClient from "./prismaClient.js";

export const checkDatabaseConnection = async () => {
    try{
        await prismaClient.$connect();
        console.log("Database Connected Successfully");
    } catch (error){
        console.error("Database Connection Failed: ", error);
    }
}