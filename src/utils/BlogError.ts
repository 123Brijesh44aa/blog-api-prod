export class BlogError extends Error {
    public statusCode: number;
    public status: string;
    public isOperational: boolean;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode

        if (statusCode >= 400 && statusCode < 500){
            this.status = "fail";
        } else if (statusCode >= 500){
            this.status = "error";
        }else {
            this.status = "success";
        }

        this.isOperational = true;

        Error.captureStackTrace(this,this.constructor);
    }
}
