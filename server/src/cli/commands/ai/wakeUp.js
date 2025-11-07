import chalk from "chalk";
import { Command } from "commander";
import yoctoSpinner from "yocto-spinner";
import { authClient } from "../../../lib/auth-client.js";
import { getStoredToken } from "../auth/login.js";
import fetch from "node-fetch";
import { auth } from "../../../lib/auth.js";
import prisma from "../../../lib/db.js";

const wakeUpAction = async () => {
  const token = await getStoredToken();

  if (!token || !token.access_token) {
    console.log(chalk.red("Not authenticated. Please login."));
    return;
  }

  const spinner = yoctoSpinner({ text: "Waking up..." });
  spinner.start();

 const user = await prisma.user.findFirst({
  where:{
    sessions:{
      some:{
        token:token.access_token,
      }
    }
  },
  select:{
    id:true,
    name:true,
    email:true,
    image:true,

  }
 })


  spinner.stop();

    console.log(chalk.bold.bgAnsi256(14)("AI Response: "), chalk.cyanBright(JSON.stringify(user)));


  console.log(chalk.green("✅ AI is awake!"));
};

export const wakeUp = new Command("wakeup").description("Wake up the AI").action(wakeUpAction);
