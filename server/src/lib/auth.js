import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import prisma from "./db.js";
import { deviceAuthorization } from "better-auth/plugins";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),
  baseURL: "http://localhost:3005",
  basePath: "/api/auth",
  trustedOrigins: ["http://localhost:3000"],
  plugins: [
    deviceAuthorization({
      // Optional configuration
      expiresIn: "30m", // Device code expiration time
      interval: "5s", // Minimum polling interval
      
    }),
  ],
  socialProviders: {
    github: {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      
    },
  
  },

    logger: {
        level: "debug"
    }
});
