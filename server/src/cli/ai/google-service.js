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
      const { textStream, finishReason, usage } = 
      streamText({
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