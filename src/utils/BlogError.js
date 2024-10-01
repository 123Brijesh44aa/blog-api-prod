export class BlogError extends Error {
     statusCode;
     status;
     isOperational;

    constructor(message, statusCode) {
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
