import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import prisma from "./db.js";
import { deviceAuthorization } from "better-auth/plugins"; 


export const auth = betterAuth({
    database: prismaAdapter(prisma, {
        provider: "postgresql", 
    }),
    plugins:[
          deviceAuthorization({ 
      // Optional configuration
      expiresIn: "30m", // Device code expiration time
      interval: "5s",    // Minimum polling interval
    }), 
    ]
});