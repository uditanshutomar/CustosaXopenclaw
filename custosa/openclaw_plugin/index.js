/**
 * Custosa Guard Plugin for OpenClaw Gateway
 * Provides prompt injection protection via three hooks:
 * - before_agent_start: Analyze user prompts
 * - before_tool_call: Validate tool invocations
 * - after_tool_call: Detect instruction laundering
 */

const HIGH_RISK_TOOLS = [
  'bash', 'shell', 'execute', 'run_command', 'terminal',
  'write_file', 'delete_file', 'move_file',
  'http_request', 'fetch', 'curl',
  'eval', 'exec'
];

async function checkPolicy(config, payload) {
  const url = config.custosaUrl || 'http://127.0.0.1:18789/custosa/policy';
  const token = config.token || '';

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) {
      console.error(`[custosa-guard] Policy check failed: ${response.status}`);
      return config.failMode === 'allow' ? { action: 'ALLOW' } : { action: 'BLOCK', reason: 'Policy check failed' };
    }

    return await response.json();
  } catch (err) {
    console.error(`[custosa-guard] Policy check error: ${err.message}`);
    return config.failMode === 'allow' ? { action: 'ALLOW' } : { action: 'BLOCK', reason: err.message };
  }
}

/**
 * Hook: before_agent_start
 * Analyzes user prompts before the agent processes them
 */
async function before_agent_start(context, config) {
  const { messages, channel } = context;

  if (!messages || messages.length === 0) {
    return { continue: true };
  }

  const userMessage = messages[messages.length - 1];
  if (userMessage.role !== 'user') {
    return { continue: true };
  }

  const content = typeof userMessage.content === 'string'
    ? userMessage.content
    : JSON.stringify(userMessage.content);

  const result = await checkPolicy(config, {
    type: 'prompt',
    content: content,
    channel: channel || 'unknown',
    hook: 'before_agent_start'
  });

  if (result.action === 'BLOCK') {
    console.warn(`[custosa-guard] BLOCKED prompt: ${result.reason}`);
    return {
      continue: false,
      response: `Request blocked by security policy: ${result.reason || 'Suspicious content detected'}`
    };
  }

  if (result.action === 'HOLD') {
    if (config.holdMode === 'block') {
      console.warn(`[custosa-guard] HOLD -> BLOCK: ${result.reason}`);
      return {
        continue: false,
        response: 'Request requires manual approval. Please try again later.'
      };
    }
  }

  // Prepend guard context if flagged
  if (result.guardContext) {
    const guardedContent = `${result.guardContext}\n\n${content}`;
    userMessage.content = guardedContent;
  }

  return { continue: true };
}

/**
 * Hook: before_tool_call
 * Validates tool invocations before execution
 */
async function before_tool_call(context, config) {
  if (!config.checkToolCalls) {
    return { continue: true };
  }

  const { tool_name, tool_input, channel } = context;

  // Check high-risk tools
  const isHighRisk = HIGH_RISK_TOOLS.some(t =>
    tool_name.toLowerCase().includes(t)
  );

  if (isHighRisk) {
    const result = await checkPolicy(config, {
      type: 'tool_call',
      tool_name: tool_name,
      tool_input: typeof tool_input === 'string' ? tool_input : JSON.stringify(tool_input),
      channel: channel || 'unknown',
      hook: 'before_tool_call',
      risk_level: 'high'
    });

    if (result.action === 'BLOCK') {
      console.warn(`[custosa-guard] BLOCKED tool call ${tool_name}: ${result.reason}`);
      return {
        continue: false,
        result: `Tool execution blocked by security policy: ${result.reason || 'High-risk operation'}`
      };
    }

    if (result.action === 'HOLD' && config.holdMode === 'block') {
      console.warn(`[custosa-guard] HOLD -> BLOCK tool call ${tool_name}`);
      return {
        continue: false,
        result: 'Tool execution requires manual approval.'
      };
    }
  }

  return { continue: true };
}

/**
 * Hook: after_tool_call
 * Detects instruction laundering in tool outputs
 */
async function after_tool_call(context, config) {
  if (!config.checkToolOutputs) {
    return { continue: true };
  }

  const { tool_name, tool_output, channel } = context;

  // Skip if output is too short to be suspicious
  const output = typeof tool_output === 'string' ? tool_output : JSON.stringify(tool_output);
  if (output.length < 50) {
    return { continue: true };
  }

  const result = await checkPolicy(config, {
    type: 'tool_output',
    tool_name: tool_name,
    content: output.slice(0, 10000), // Limit size
    channel: channel || 'unknown',
    hook: 'after_tool_call'
  });

  if (result.action === 'BLOCK') {
    console.warn(`[custosa-guard] BLOCKED tool output from ${tool_name}: ${result.reason}`);
    return {
      continue: true, // Allow but sanitize
      tool_output: `[Content filtered by security policy: ${result.reason || 'Suspicious content detected'}]`
    };
  }

  if (result.warning) {
    console.warn(`[custosa-guard] WARNING in tool output from ${tool_name}: ${result.warning}`);
  }

  return { continue: true };
}

module.exports = {
  before_agent_start,
  before_tool_call,
  after_tool_call
};
