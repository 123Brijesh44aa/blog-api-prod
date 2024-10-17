import crypto from "crypto";
import prismaClient from "../prismaClient.js";


console.log(crypto.randomBytes(32).toString('hex'));


// const data = async () => {
//     return await prismaClient.user.findFirst({
//         where: {
//             email : "oddsworld0121@gmail.com",
//             verificationToken: "hello-this-is-brijesh"
//         }
//     })
// }


// data().then((data) => {
//     console.log(data);
// }).catch((error) => {
//     console.log(error);
// })