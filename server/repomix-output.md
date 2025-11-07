This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
.gitignore
package.json
prisma/migrations/20251104095426_authentication/migration.sql
prisma/migrations/20251106054258_conversation_model_added/migration.sql
prisma/migrations/migration_lock.toml
prisma/schema.prisma
src/cli/ai/google-service.js
src/cli/commands/ai/wakeUp.js
src/cli/commands/auth/login.js
src/cli/main.js
src/config/google.config.js
src/index.js
src/lib/auth-client.js
src/lib/auth.js
src/lib/db.js
src/services/chat.services.js
```

# Files

## File: .gitignore
```
node_modules
# Keep environment variables out of version control
.env

/src/generated/prisma
```

## File: package.json
```json
{
  "name": "server",
  "version": "1.0.0",
  "description": "",
  "main": "src/index.js",
  "bin": {
    "orbit": "src/cli/main.js"
  },
  "scripts": {
    "dev": "nodemon src/index.js",
    "cli": "node src/cli/main.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "type": "module",
  "dependencies": {
    "@ai-sdk/google": "^2.0.28",
    "@clack/prompts": "^0.11.0",
    "@prisma/client": "^6.18.0",
    "ai": "^5.0.87",
    "better-auth": "^1.3.34",
    "boxen": "^8.0.1",
    "chalk": "^5.6.2",
    "commander": "^14.0.2",
    "cors": "^2.8.5",
    "dotenv": "^17.2.3",
    "express": "^5.1.0",
    "figlet": "^1.9.3",
    "inquirer": "^12.10.0",
    "open": "^10.2.0",
    "ora": "^9.0.0",
    "prisma": "^6.18.0",
    "yocto-spinner": "^1.0.0",
    "zod": "^4.1.12"
  }
}
```

## File: prisma/migrations/20251104095426_authentication/migration.sql
```sql
-- CreateTable
CREATE TABLE "user" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT NOT NULL,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account" (
    "id" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "idToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMP(3),
    "refreshTokenExpiresAt" TIMESTAMP(3),
    "scope" TEXT,
    "password" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "verification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "deviceCode" (
    "id" TEXT NOT NULL,
    "deviceCode" TEXT NOT NULL,
    "userCode" TEXT NOT NULL,
    "userId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL,
    "lastPolledAt" TIMESTAMP(3),
    "pollingInterval" INTEGER,
    "clientId" TEXT,
    "scope" TEXT,

    CONSTRAINT "deviceCode_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE UNIQUE INDEX "session_token_key" ON "session"("token");

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account" ADD CONSTRAINT "account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
```

## File: prisma/migrations/20251106054258_conversation_model_added/migration.sql
```sql
-- CreateTable
CREATE TABLE "Conversation" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "title" TEXT,
    "mode" TEXT NOT NULL DEFAULT 'chat',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Conversation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Message" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Message_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Message_conversationId_idx" ON "Message"("conversationId");

-- AddForeignKey
ALTER TABLE "Conversation" ADD CONSTRAINT "Conversation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Message" ADD CONSTRAINT "Message_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "Conversation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
```

## File: prisma/migrations/migration_lock.toml
```toml
# Please do not edit this file manually
# It should be added in your version-control system (e.g., Git)
provider = "postgresql"
```

## File: prisma/schema.prisma
```
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?
// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init

generator client {
  provider = "prisma-client-js"

}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id            String    @id 
  name          String
  email         String
  emailVerified Boolean   @default(false)
  image         String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @default(now()) @updatedAt
  sessions      Session[]
  accounts      Account[]

  conversation Conversation[]

  @@unique([email])
  @@map("user")
}

model Session {
  id        String   @id
  expiresAt DateTime
  token     String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  ipAddress String?
  userAgent String?
  userId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([token])
  @@map("session")
}

model Account {
  id                    String    @id
  accountId             String
  providerId            String
  userId                String
  user                  User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  accessToken           String?
  refreshToken          String?
  idToken               String?
  accessTokenExpiresAt  DateTime?
  refreshTokenExpiresAt DateTime?
  scope                 String?
  password              String?
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt

  @@map("account")
}

model Verification {
  id         String   @id
  identifier String
  value      String
  expiresAt  DateTime
  createdAt  DateTime @default(now())
  updatedAt  DateTime @default(now()) @updatedAt

  @@map("verification")
}

model DeviceCode {
  id              String    @id
  deviceCode      String
  userCode        String
  userId          String?
  expiresAt       DateTime
  status          String
  lastPolledAt    DateTime?
  pollingInterval Int?
  clientId        String?
  scope           String?

  @@map("deviceCode")
}

model Conversation {
  id  String @id @default(cuid())
  userId String
  title  String?
  mode  String @default("chat") // chat , tool , agent
  createdAt DateTime @default(now())
  updatedAt DateTime @default(now()) @updatedAt

  user    User    @relation(fields: [userId], references: [id], onDelete: Cascade)
  messages  Message[]

}

model Message {
  id             String   @id @default(cuid())
  conversationId String
  role           String   // user, assistant, system, tool
  content        String   // JSON string for complex content
  createdAt      DateTime @default(now())
  
  conversation Conversation @relation(fields: [conversationId], references: [id], onDelete: Cascade)
  
  @@index([conversationId])
}
```

## File: src/cli/ai/google-service.js
```javascript
import { google } from "@ai-sdk/google";
import { streamText } from "ai";
import { config } from "../config/google.config.js";
import chalk from "chalk";

export class AIService {
  constructor() {
    if (!config.googleApiKey) {
      throw new Error("GOOGLE_API_KEY is not set in environment variables");
    }
    
    this.model = google(config.model, {
      apiKey: config.googleApiKey,
    });
  }

  /**
   * Send a message and get streaming response
   * @param {Array} messages - Array of message objects {role, content}
   * @param {Function} onChunk - Callback for each text chunk
   * @returns {Promise<string>} Full response text
   */
  async sendMessage(messages, onChunk) {
    try {
      const { textStream, finishReason, usage } = streamText({
        model: this.model,
        messages: messages,
        temperature: config.temperature,
        maxTokens: config.maxTokens,
      });

      let fullResponse = "";
      
      for await (const chunk of textStream) {
        fullResponse += chunk;
        if (onChunk) {
          onChunk(chunk);
        }
      }

      return {
        content: fullResponse,
        finishReason,
        usage,
      };
    } catch (error) {
      console.error(chalk.red("AI Service Error:"), error.message);
      throw error;
    }
  }

  /**
   * Get a non-streaming response
   * @param {Array} messages - Array of message objects
   * @returns {Promise<string>} Response text
   */
  async getMessage(messages) {
    let fullResponse = "";
    await this.sendMessage(messages, (chunk) => {
      fullResponse += chunk;
    });
    return fullResponse;
  }
}
```

## File: src/cli/commands/ai/wakeUp.js
```javascript
import chalk from "chalk";
import { Command } from "commander";
import { cancel, confirm, intro, isCancel, outro } from "@clack/prompts";
import yoctoSpinner from "yocto-spinner";
import { authClient } from "../../../lib/auth-client.js";


const wakeUpAction = async () => {
    const {data , error} = await authClient.getSession();
    const spinner = yoctoSpinner({ text: "Waking up..." });
    spinner.start();

    setTimeout(() => {
        spinner.stop();
        console.log(chalk.green("✅ AI is awake!"));
    }, 1000);

    console.log(chalk.green(`Hello ${data?.user?.name}! Select the options below to get started.`));
}


export const wakeUp = new Command("wakeup").description("Wake up the AI").action(wakeUpAction)
```

## File: src/cli/commands/auth/login.js
```javascript
import { cancel, confirm, intro, isCancel, outro } from "@clack/prompts";
import { logger } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import chalk from "chalk";
import { Command } from "commander";
import fs from "fs/promises";
import open from "open";
import os from "os";
import path from "path";
import yoctoSpinner from "yocto-spinner";
import * as z from "zod/v4";
import dotenv from "dotenv";

dotenv.config();

const DEMO_URL = "http://localhost:3005";
const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CONFIG_DIR = path.join(os.homedir(), ".better-auth");
const TOKEN_FILE = path.join(CONFIG_DIR, "token.json");

// ============================================
// TOKEN MANAGEMENT (Export these for use in other commands)
// ============================================

export async function getStoredToken() {
  try {
    const data = await fs.readFile(TOKEN_FILE, "utf-8");
    const token = JSON.parse(data);
    return token;
  } catch (error) {
    // File doesn't exist or can't be read
    return null;
  }
}

export async function storeToken(token) {
  try {
    // Ensure config directory exists
    await fs.mkdir(CONFIG_DIR, { recursive: true });

    // Store token with metadata
    const tokenData = {
      access_token: token.access_token,
      refresh_token: token.refresh_token, // Store if available
      token_type: token.token_type || "Bearer",
      scope: token.scope,
      expires_at: token.expires_in
        ? new Date(Date.now() + token.expires_in * 1000).toISOString()
        : null,
      created_at: new Date().toISOString(),
    };

    await fs.writeFile(TOKEN_FILE, JSON.stringify(tokenData, null, 2), "utf-8");
    return true;
  } catch (error) {
    console.error(chalk.red("Failed to store token:"), error.message);
    return false;
  }
}

export async function clearStoredToken() {
  try {
    await fs.unlink(TOKEN_FILE);
    return true;
  } catch (error) {
    // File doesn't exist or can't be deleted
    return false;
  }
}

export async function isTokenExpired() {
  const token = await getStoredToken();
  if (!token || !token.expires_at) {
    return true;
  }

  const expiresAt = new Date(token.expires_at);
  const now = new Date();

  // Consider expired if less than 5 minutes remaining
  return expiresAt.getTime() - now.getTime() < 5 * 60 * 1000;
}

export async function requireAuth() {
  const token = await getStoredToken();

  if (!token) {
    console.log(
      chalk.red("❌ Not authenticated. Please run 'your-cli login' first.")
    );
    process.exit(1);
  }

  if (await isTokenExpired()) {
    console.log(
      chalk.yellow("⚠️  Your session has expired. Please login again.")
    );
    console.log(chalk.gray("   Run: your-cli login\n"));
    process.exit(1);
  }

  return token;
}

// ============================================
// LOGIN COMMAND
// ============================================

export async function loginAction(opts) {
  const options = z
    .object({
      serverUrl: z.string().optional(),
      clientId: z.string().optional(),
    })
    .parse(opts);

  const serverUrl = options.serverUrl || DEMO_URL;
  const clientId = options.clientId || CLIENT_ID;

  intro(chalk.bold("🔐 Better Auth CLI Login"));

  if (!clientId) {
    logger.error("CLIENT_ID is not set in .env file");
    console.log(
      chalk.red("\n❌ Please set GITHUB_CLIENT_ID in your .env file")
    );
    process.exit(1);
  }

  // Check if already logged in
  const existingToken = await getStoredToken();
  const expired = await isTokenExpired();

  if (existingToken && !expired) {
    const shouldReauth = await confirm({
      message: "You're already logged in. Do you want to log in again?",
      initialValue: false,
    });

    if (isCancel(shouldReauth) || !shouldReauth) {
      cancel("Login cancelled");
      process.exit(0);
    }
  }

  // Create the auth client
  const authClient = createAuthClient({
    baseURL: serverUrl,
    plugins: [deviceAuthorizationClient()],
  });

  const spinner = yoctoSpinner({ text: "Requesting device authorization..." });
  spinner.start();

  try {
    // Request device code
    const { data, error } = await authClient.device.code({
      client_id: clientId,
      scope: "openid profile email",
    });

    spinner.stop();

    if (error || !data) {
      logger.error(
        `Failed to request device authorization: ${
          error?.error_description || error?.message || "Unknown error"
        }`
      );

      if (error?.status === 404) {
        console.log(chalk.red("\n❌ Device authorization endpoint not found."));
        console.log(chalk.yellow("   Make sure your auth server is running."));
      } else if (error?.status === 400) {
        console.log(
          chalk.red("\n❌ Bad request - check your CLIENT_ID configuration.")
        );
      }

      process.exit(1);
    }

    const {
      device_code,
      user_code,
      verification_uri,
      verification_uri_complete,
      interval = 5,
      expires_in,
    } = data;

    // Display authorization instructions
    console.log("");
    console.log(chalk.cyan("📱 Device Authorization Required"));
    console.log("");
    console.log(
      `Please visit: ${chalk.underline.blue(
        verification_uri_complete || verification_uri
      )}`
    );
    console.log(`Enter code: ${chalk.bold.green(user_code)}`);
    console.log("");

    // Ask if user wants to open browser
    const shouldOpen = await confirm({
      message: "Open browser automatically?",
      initialValue: true,
    });

    if (!isCancel(shouldOpen) && shouldOpen) {
      const urlToOpen = verification_uri_complete || verification_uri;
      await open(urlToOpen);
    }

    // Start polling
    console.log(
      chalk.gray(
        `Waiting for authorization (expires in ${Math.floor(
          expires_in / 60
        )} minutes)...`
      )
    );

    const token = await pollForToken(
      authClient,
      device_code,
      clientId,
      interval
    );

    if (token) {
      // Store the token
      const saved = await storeToken(token);

      if (!saved) {
        console.log(
          chalk.yellow("\n⚠️  Warning: Could not save authentication token.")
        );
        console.log(
          chalk.yellow("   You may need to login again on next use.")
        );
      }

      // Get user info
      const { data: session } = await authClient.getSession({
        fetchOptions: {
          headers: {
            Authorization: `Bearer ${token.access_token}`,
          },
        },
      });

      outro(
        chalk.green(
          `✅ Login successful! Welcome ${
            session?.user?.name || session?.user?.email || "User"
          }`
        )
      );

      console.log(chalk.gray(`\n📁 Token saved to: ${TOKEN_FILE}`));
      console.log(
        chalk.gray("   You can now use AI commands without logging in again.\n")
      );
    }
  } catch (err) {
    spinner.stop();
    console.error(chalk.red("\nLogin failed:"), err.message);
    process.exit(1);
  }
}

async function pollForToken(authClient, deviceCode, clientId, initialInterval) {
  let pollingInterval = initialInterval;
  const spinner = yoctoSpinner({ text: "", color: "cyan" });
  let dots = 0;

  return new Promise((resolve, reject) => {
    const poll = async () => {
      dots = (dots + 1) % 4;
      spinner.text = chalk.gray(
        `Polling for authorization${".".repeat(dots)}${" ".repeat(3 - dots)}`
      );
      if (!spinner.isSpinning) spinner.start();

      try {
        const { data, error } = await authClient.device.token({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
          client_id: clientId,
          fetchOptions: {
            headers: {
              "user-agent": `Better Auth CLI`,
            },
          },
        });

        if (data?.access_token) {
          spinner.stop();
          resolve(data);
          return;
        } else if (error) {
          switch (error.error) {
            case "authorization_pending":
              break;
            case "slow_down":
              pollingInterval += 5;
              break;
            case "access_denied":
              spinner.stop();
              logger.error("Access was denied by the user");
              process.exit(1);
              break;
            case "expired_token":
              spinner.stop();
              logger.error("The device code has expired. Please try again.");
              process.exit(1);
              break;
            default:
              spinner.stop();
              logger.error(`Error: ${error.error_description}`);
              process.exit(1);
          }
        }
      } catch (err) {
        spinner.stop();
        logger.error(`Network error: ${err.message}`);
        process.exit(1);
      }

      setTimeout(poll, pollingInterval * 1000);
    };

    setTimeout(poll, pollingInterval * 1000);
  });
}

// ============================================
// LOGOUT COMMAND
// ============================================

export async function logoutAction() {
  intro(chalk.bold("👋 Logout"));

  const token = await getStoredToken();

  if (!token) {
    console.log(chalk.yellow("You're not logged in."));
    process.exit(0);
  }

  const shouldLogout = await confirm({
    message: "Are you sure you want to logout?",
    initialValue: false,
  });

  if (isCancel(shouldLogout) || !shouldLogout) {
    cancel("Logout cancelled");
    process.exit(0);
  }

  const cleared = await clearStoredToken();

  if (cleared) {
    outro(chalk.green("✅ Successfully logged out!"));
  } else {
    console.log(chalk.yellow("⚠️  Could not clear token file."));
  }
}

// ============================================
// WHOAMI COMMAND
// ============================================

export async function whoamiAction(opts) {
  const options = z
    .object({
      serverUrl: z.string().optional(),
    })
    .parse(opts);

  const serverUrl = options.serverUrl || DEMO_URL;

  intro(chalk.bold("👤 Current User"));

  const token = await requireAuth();

  if (token) {
    console.log(chalk.gray(`\n✅ Token loaded from: ${TOKEN_FILE}`));
  }

  const spinner = yoctoSpinner({ text: "Fetching user info..." });
  spinner.start();

  try {
    // Call your backend's /api/me route with the Bearer token
    const response = await fetch(`${serverUrl}/api/me`);

    spinner.stop();

    if (!response.ok) {
      const errorText = await response.text();
      console.log(
        chalk.red(`\n❌ Failed to fetch user info (${response.status})`)
      );
      console.log(chalk.gray(`   ${errorText}`));

      if (response.status === 401) {
        console.log(chalk.yellow("\n   Your token may be invalid or expired."));
        console.log(chalk.gray("   Try: your-cli login\n"));
      }
      return;
    }

    const data = await response.json();

    if (!data?.user) {
      console.log(chalk.yellow("\n⚠️  No user data returned from server"));
      console.log(chalk.gray("   Response:"), JSON.stringify(data, null, 2));
      return;
    }

    console.log("");
    console.log(chalk.cyan("User Information:"));
    console.log(chalk.gray(`  Name: ${data.user.name || "N/A"}`));
    console.log(chalk.gray(`  Email: ${data.user.email || "N/A"}`));
    console.log(chalk.gray(`  ID: ${data.user.id || "N/A"}`));

    if (token.expires_at) {
      const expiresAt = new Date(token.expires_at);
      const now = new Date();
      const daysLeft = Math.round(
        (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
      );
      console.log(
        chalk.gray(
          `  Token expires: ${expiresAt.toLocaleString()} (in ${daysLeft} days)`
        )
      );
    }

    console.log("");
  } catch (err) {
    spinner.stop();
    console.error(chalk.red("\n❌ Failed to fetch user info:"), err.message);
    console.log(chalk.gray("\nTry running 'your-cli login' again.\n"));
  }
}

// ============================================
// COMMANDER SETUP
// ============================================

export const login = new Command("login")
  .description("Login to Better Auth")
  .option("--server-url <url>", "The Better Auth server URL", DEMO_URL)
  .option("--client-id <id>", "The OAuth client ID", CLIENT_ID)
  .action(loginAction);

export const logout = new Command("logout")
  .description("Logout and clear stored credentials")
  .action(logoutAction);

export const whoami = new Command("whoami")
  .description("Show current authenticated user")
  .option("--server-url <url>", "The Better Auth server URL", DEMO_URL)
  .action(whoamiAction);
```

## File: src/cli/main.js
```javascript
#!/usr/bin/env node

import dotenv from "dotenv";

import chalk from "chalk";
import figlet from "figlet";

import { Command } from "commander";

import { login, logout, whoami } from "./commands/auth/login.js";
import { wakeUp } from "./commands/ai/wakeUp.js";

dotenv.config();

async function main() {
    // Display banner
    console.log(
        chalk.cyan(
            figlet.textSync("Orbit CLI", {
                font: "Standard",
                horizontalLayout: "default",
            })
        )
    );
    console.log(chalk.gray("A Cli based AI tool \n"));

    const program = new Command("orbit");
    
    program
        .version("0.0.1")
        .description("Orbit CLI - Device Flow Authentication");

    // Add commands
    program.addCommand(wakeUp);
    program.addCommand(login);
    program.addCommand(logout);
    program.addCommand(whoami);


    // Default action shows help
    program.action(() => {
        program.help();
    });

    program.parse();
}

main().catch((error) => {
    console.error(chalk.red("Error running Orbit CLI:"), error);
    process.exit(1);
});
```

## File: src/config/google.config.js
```javascript
import dotenv from 'dotenv';
dotenv.config();

export const config = {
  googleApiKey: process.env.GOOGLE_GENERATIVE_AI_API_KEY || '',
  model: process.env.ORBITAI_MODEL || 'gemini-1.5-flash',
};
```

## File: src/index.js
```javascript
import express from "express";

import { auth } from "./lib/auth.js";
import { fromNodeHeaders ,toNodeHandler} from "better-auth/node";
import cors from "cors";

const app = express();
const port = 3005;

app.use(
  cors({
    origin: "http://localhost:3000", 
    methods: ["GET", "POST", "PUT", "DELETE"], 
    credentials: true, 
  })
);

app.all("/api/auth/*splat", toNodeHandler(auth)); 

app.use(express.json());

app.get("/api/me", async (req, res) => {
 	const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });
 	return res.json(session);
});



app.get("/device" , async (req, res) => {
  const {user_code} = req.params;

  res.redirect(`http://localhost:3000/device?user_code=${user_code}`);
})

app.listen(port, () => {

	console.log(`Example app listening on port ${port}`);
});
```

## File: src/lib/auth-client.js
```javascript
import { deviceAuthorizationClient } from "better-auth/client/plugins"
import { createAuthClient } from "better-auth/client"

export const authClient = createAuthClient({
    baseURL: "http://localhost:3005",
      plugins: [ 
    deviceAuthorizationClient(), 
  ], 
})
```

## File: src/lib/auth.js
```javascript
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
```

## File: src/lib/db.js
```javascript
import {PrismaClient} from "@prisma/client";

const globalForPrisma = global
const prisma = new PrismaClient();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;

export default prisma
```

## File: src/services/chat.services.js
```javascript
import {prisma} from "../lib/db.js"
import {auth} from "../lib/auth.js";

export class ChatService {
  /**
   * Create a new conversation
   * @param {string} userId - User ID
   * @param {string} mode - chat, tool, or agent
   * @param {string} title - Optional conversation title
   */
  async createConversation( userId , mode = "chat", title = null) {
  
    return await prisma.conversation.create({
      data: {
        userId,
        mode,
        title: title || `New ${mode} conversation`,
      },
    });
  }

  /**
   * Get or create a conversation for user
   * @param {string} userId - User ID
   * @param {string} conversationId - Optional conversation ID
   * @param {string} mode - chat, tool, or agent
   */
  async getOrCreateConversation(userId, conversationId = null, mode = "chat") {
    if (conversationId) {
      const conversation = await prisma.conversation.findFirst({
        where: {
          id: conversationId,
          userId,
        },
        include: {
          messages: {
            orderBy: { createdAt: "asc" },
          },
        },
      });

      if (conversation) return conversation;
    }

    // Create new conversation if not found or not provided
    return await this.createConversation(userId, mode);
  }

  /**
   * Add a message to conversation
   * @param {string} conversationId - Conversation ID
   * @param {string} role - user, assistant, system, tool
   * @param {string|object} content - Message content
   */
  async addMessage(conversationId, role, content) {
    // Convert content to JSON string if it's an object
    const contentStr = typeof content === "string" 
      ? content 
      : JSON.stringify(content);

    return await prisma.message.create({
      data: {
        conversationId,
        role,
        content: contentStr,
      },
    });
  }

  /**
   * Get conversation messages
   * @param {string} conversationId - Conversation ID
   */
  async getMessages(conversationId) {
    const messages = await prisma.message.findMany({
      where: { conversationId },
      orderBy: { createdAt: "asc" },
    });

    // Parse JSON content back to objects if needed
    return messages.map((msg) => ({
      ...msg,
      content: this.parseContent(msg.content),
    }));
  }

  /**
   * Get all conversations for a user
   * @param {string} userId - User ID
   */
  async getUserConversations(userId) {
    return await prisma.conversation.findMany({
      where: { userId },
      orderBy: { updatedAt: "desc" },
      include: {
        messages: {
          take: 1,
          orderBy: { createdAt: "desc" },
        },
      },
    });
  }

  /**
   * Delete a conversation
   * @param {string} conversationId - Conversation ID
   * @param {string} userId - User ID (for security)
   */
  async deleteConversation(conversationId, userId) {
    return await prisma.conversation.deleteMany({
      where: {
        id: conversationId,
        userId,
      },
    });
  }

  /**
   * Update conversation title
   * @param {string} conversationId - Conversation ID
   * @param {string} title - New title
   */
  async updateTitle(conversationId, title) {
    return await prisma.conversation.update({
      where: { id: conversationId },
      data: { title },
    });
  }

  /**
   * Helper to parse content (JSON or string)
   */
  parseContent(content) {
    try {
      return JSON.parse(content);
    } catch {
      return content;
    }
  }

  /**
   * Format messages for AI SDK
   * @param {Array} messages - Database messages
   */
  formatMessagesForAI(messages) {
    return messages.map((msg) => ({
      role: msg.role,
      content: typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content),
    }));
  }
}
```
