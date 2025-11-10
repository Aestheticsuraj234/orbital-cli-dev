import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);

/**
 * System prompt for agent mode - instructs AI to generate complete applications
 */
const AGENT_SYSTEM_PROMPT = `You are an expert software engineer specializing in creating complete, production-ready applications from descriptions.

Your task is to generate a complete application with all necessary files, dependencies, and setup instructions.

CRITICAL INSTRUCTIONS:
1. Generate ALL files needed for the application to run
2. Include package.json, README.md, and any configuration files
3. Provide bash commands for setup and execution
4. Format your response using this EXACT structure:

\`\`\`STRUCTURE
folder-name/
├── file1.ext
├── file2.ext
└── subfolder/
    └── file3.ext
\`\`\`

Then for each file, use this format:

\`\`\`file:folder-name/file1.ext
[file content here]
\`\`\`

\`\`\`file:folder-name/file2.ext
[file content here]
\`\`\`

Finally, provide bash commands in this format:

\`\`\`bash
# Setup commands
cd folder-name
npm install
npm run dev
\`\`\`

IMPORTANT RULES:
- Create a meaningful, descriptive folder name (use kebab-case)
- Include ALL dependencies in package.json with correct versions
- Make code clean, well-commented, and production-ready
- Provide complete, working applications (no placeholders!)
- Include error handling and input validation
- Add proper README with clear instructions
- Use modern JavaScript/TypeScript practices
- Include .gitignore and other config files
- Make sure all imports and paths are correct
- Test that the code would actually run

EXAMPLE OUTPUT FORMAT:

\`\`\`STRUCTURE
todo-app/
├── package.json
├── README.md
├── .gitignore
├── index.html
└── src/
    ├── App.jsx
    └── main.jsx
\`\`\`

\`\`\`file:todo-app/package.json
{
  "name": "todo-app",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite"
  },
  "dependencies": {
    "react": "^18.2.0"
  }
}
\`\`\`

\`\`\`file:todo-app/README.md
# Todo App
...
\`\`\`

\`\`\`bash
# Navigate to project
cd todo-app

# Install dependencies
npm install

# Start development server
npm run dev
\`\`\`

Remember: Generate COMPLETE, WORKING code. No TODOs or placeholders!`;

/**
 * Console logging helpers
 */
function printSystem(message) {
  console.log(message);
}

function printAssistantStart() {
  console.log(chalk.magenta('\n🤖 Agent Response:\n'));
}

function printAssistantChunk(chunk) {
  process.stdout.write(chalk.gray(chunk));
}

function printAssistantEnd() {
  console.log(chalk.magenta('\n\n─────────────────────────────────────\n'));
}

/**
 * Parse file content from AI response
 * Handles both ```file:path and ```filename formats
 */
function parseFilesFromResponse(response) {
  const files = [];
  
  // Primary format: ```file:path
  const fileRegex1 = /```file:([^\n]+)\n([\s\S]*?)```/g;
  let match;
  
  while ((match = fileRegex1.exec(response)) !== null) {
    const filePath = match[1].trim();
    const content = match[2].trim();
    
    // Skip if this looks like a bash block
    if (!filePath.includes('bash')) {
      files.push({ path: filePath, content });
    }
  }
  
  // Alternative format: Look for code blocks with file paths in comments
  // Example: ```javascript // src/App.jsx
  const fileRegex2 = /```(\w+)\s*(?:\/\/|#)\s*([^\n]+)\n([\s\S]*?)```/g;
  
  while ((match = fileRegex2.exec(response)) !== null) {
    const language = match[1].trim();
    const filePath = match[2].trim();
    const content = match[3].trim();
    
    // Only add if not already added and looks like a file path
    if (filePath.includes('/') || filePath.includes('.')) {
      const exists = files.some(f => f.path === filePath);
      if (!exists) {
        files.push({ path: filePath, content });
      }
    }
  }
  
  return files;
}

/**
 * Parse bash commands from AI response
 */
function parseBashCommands(response) {
  const commands = [];
  const bashRegex = /```bash\n([\s\S]*?)```/g;
  let match;
  
  while ((match = bashRegex.exec(response)) !== null) {
    const commandBlock = match[1].trim();
    
    // Split by lines and filter out empty lines and pure comments
    const lines = commandBlock.split('\n').map(line => line.trim()).filter(line => {
      return line && !line.startsWith('#');
    });
    
    commands.push(...lines);
  }
  
  return commands;
}

/**
 * Get folder name from structure or files
 */
function getFolderName(response, files) {
  // Try to extract from STRUCTURE block
  const structureMatch = response.match(/```STRUCTURE\n([\s\S]*?)```/);
  if (structureMatch) {
    const firstLine = structureMatch[1].trim().split('\n')[0];
    const folderMatch = firstLine.match(/^([a-z0-9-_]+)\//i);
    if (folderMatch) {
      return folderMatch[1];
    }
  }
  
  // Extract from first file path
  if (files.length > 0) {
    const parts = files[0].path.split('/');
    if (parts.length > 1) {
      return parts[0];
    }
  }
  
  // Generate timestamp-based name as fallback
  const timestamp = new Date().getTime();
  return `app-${timestamp}`;
}

/**
 * Create application from AI response
 */
async function createApplicationFiles(baseDir, folderName, files) {
  const appDir = path.join(baseDir, folderName);
  
  // Create main directory
  await fs.mkdir(appDir, { recursive: true });
  printSystem(chalk.cyan(`📁 Created directory: ${folderName}/`));
  
  // Write all files
  for (const file of files) {
    // Remove folder prefix if it exists in the path
    let relativePath = file.path;
    if (relativePath.startsWith(folderName + '/')) {
      relativePath = relativePath.substring(folderName.length + 1);
    }
    
    const filePath = path.join(appDir, relativePath);
    const fileDir = path.dirname(filePath);
    
    // Create directory structure if needed
    await fs.mkdir(fileDir, { recursive: true });
    
    // Write file
    await fs.writeFile(filePath, file.content, 'utf8');
    printSystem(chalk.green(`  ✓ ${relativePath}`));
  }
  
  return appDir;
}

/**
 * Display file tree structure
 */
function displayFileTree(files, folderName) {
  printSystem(chalk.cyan('\n📂 Project Structure:'));
  printSystem(chalk.white(`${folderName}/`));
  
  // Group files by directory
  const filesByDir = {};
  files.forEach(file => {
    let relativePath = file.path;
    if (relativePath.startsWith(folderName + '/')) {
      relativePath = relativePath.substring(folderName.length + 1);
    }
    
    const parts = relativePath.split('/');
    const dir = parts.length > 1 ? parts.slice(0, -1).join('/') : '';
    
    if (!filesByDir[dir]) {
      filesByDir[dir] = [];
    }
    filesByDir[dir].push(parts[parts.length - 1]);
  });
  
  // Display tree
  Object.keys(filesByDir).sort().forEach(dir => {
    if (dir) {
      printSystem(chalk.white(`├── ${dir}/`));
      filesByDir[dir].forEach(file => {
        printSystem(chalk.white(`│   └── ${file}`));
      });
    } else {
      filesByDir[dir].forEach(file => {
        printSystem(chalk.white(`├── ${file}`));
      });
    }
  });
}

/**
 * Generate application using agent mode
 */
export async function generateApplication(description, aiService, cwd = process.cwd()) {
  try {
    printSystem(chalk.cyan('\n🤖 Agent Mode: Generating your application...\n'));
    printSystem(chalk.gray(`Request: ${description}\n`));
    
    // Create messages array
    const messages = [
      {
        role: 'user',
        content: `Create a complete application for: ${description}\n\nRemember to follow the EXACT format with STRUCTURE block, file: blocks, and bash blocks.`
      }
    ];
    
    // Get AI response with system prompt
    let response = '';
    
    printAssistantStart();
    
    try {
      const result = await aiService.sendMessage(
        [
          { role: 'system', content: AGENT_SYSTEM_PROMPT },
          ...messages
        ],
        (chunk) => {
          response += chunk;
          printAssistantChunk(chunk);
        }
      );
      
      response = result.content || response;
      printAssistantEnd();
      
    } catch (err) {
      printAssistantEnd();
      throw new Error(`AI generation failed: ${err.message}`);
    }
    
    // Parse files and commands
    const files = parseFilesFromResponse(response);
    const bashCommands = parseBashCommands(response);
    const folderName = getFolderName(response, files);
    
    if (files.length === 0) {
      printSystem(chalk.yellow('\n⚠️  No files found in response.'));
      printSystem(chalk.yellow('The AI might not have followed the required format.\n'));
      printSystem(chalk.dim('Expected format: ```file:folder/filename.ext\n[content]\n```\n'));
      printSystem(chalk.dim('Raw response preview:\n'));
      printSystem(chalk.dim(response.substring(0, 800) + '...\n'));
      
      // Save full response to a file for debugging
      const debugFile = path.join(cwd, 'agent-debug-response.txt');
      await fs.writeFile(debugFile, response, 'utf8');
      printSystem(chalk.dim(`Full response saved to: ${debugFile}\n`));
      
      return null;
    }
    
    printSystem(chalk.green(`\n✅ Parsed ${files.length} file(s) from AI response\n`));
    
    // Display file tree
    displayFileTree(files, folderName);
    
    // Create application directory and files
    printSystem(chalk.cyan('\n📝 Creating files...\n'));
    const appDir = await createApplicationFiles(cwd, folderName, files);
    
    // Display results
    printSystem(chalk.green.bold(`\n✨ Application created successfully!\n`));
    printSystem(chalk.cyan(`📁 Location: ${chalk.bold(appDir)}\n`));
    
    // Display bash commands
    if (bashCommands.length > 0) {
      printSystem(chalk.cyan('📋 Next Steps:\n'));
      printSystem(chalk.white('```bash'));
      bashCommands.forEach(cmd => {
        printSystem(chalk.white(cmd));
      });
      printSystem(chalk.white('```\n'));
    } else {
      printSystem(chalk.yellow('⚠️  No setup commands found in response\n'));
      printSystem(chalk.gray('You may need to manually set up the project\n'));
    }
    
    return {
      folderName,
      appDir,
      files: files.map(f => f.path),
      commands: bashCommands,
      success: true,
    };
    
  } catch (err) {
    printSystem(chalk.red(`\n❌ Error generating application: ${err.message}\n`));
    if (err.stack) {
      printSystem(chalk.dim(err.stack + '\n'));
    }
    throw err;
  }
}

/**
 * Example usage:
 * 
 * import { AIService } from './ai/google-service.js';
 * import { generateApplication } from './agent-mode.js';
 * 
 * const aiService = new AIService();
 * const result = await generateApplication(
 *   'Build a todo app with React and Tailwind CSS',
 *   aiService,
 *   process.cwd()
 * );
 */