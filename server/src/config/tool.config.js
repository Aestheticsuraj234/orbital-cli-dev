import { google } from '@ai-sdk/google';

/**
 * Available Google Generative AI tools configuration
 */
export const availableTools = [
  {
    id: 'google_search',
    name: 'Google Search',
    description: 'Access the latest information using Google search. Useful for current events, news, and real-time information.',
    tool: () => google.tools.googleSearch({}),
    enabled: false,
  },
  {
    id: 'code_execution',
    name: 'Code Execution',
    description: 'Generate and execute Python code to perform calculations, solve problems, or provide accurate information.',
    tool: () => google.tools.codeExecution({}),
    enabled: false,
  },
];

/**
 * Get enabled tools as a tools object for AI SDK
 */
export function getEnabledTools() {
  const tools = {};
  for (const toolConfig of availableTools) {
    if (toolConfig.enabled) {
      tools[toolConfig.id] = toolConfig.tool();
    }
  }
  return Object.keys(tools).length > 0 ? tools : undefined;
}

/**
 * Toggle a tool's enabled state
 */
export function toggleTool(toolId) {
  const tool = availableTools.find(t => t.id === toolId);
  if (tool) {
    tool.enabled = !tool.enabled;
    return tool.enabled;
  }
  return false;
}

/**
 * Enable specific tools
 */
export function enableTools(toolIds) {
  availableTools.forEach(tool => {
    tool.enabled = toolIds.includes(tool.id);
  });
}

/**
 * Get all enabled tool names
 */
export function getEnabledToolNames() {
  return availableTools.filter(t => t.enabled).map(t => t.name);
}

/**
 * Reset all tools (disable all)
 */
export function resetTools() {
  availableTools.forEach(tool => {
    tool.enabled = false;
  });
}
