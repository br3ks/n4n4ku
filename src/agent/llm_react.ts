import { RECON_TOOLS_SCHEMA } from "./tools_schema.js";

export interface ReActLlmResponse {
  content: string;
  toolCalls: Array<{
    id: string;
    name: string;
    arguments: any;
  }>;
}

export async function callLlmReActStep(
  messages: any[],
  config: { apiKey?: string; baseUrl?: string; model?: string },
  onContentChunk?: (chunk: string) => void
): Promise<ReActLlmResponse> {
  const apiKey = config.apiKey || process.env.LLM_API_KEY || "dummy";
  let baseUrl = (config.baseUrl || process.env.LLM_BASE_URL || "http://localhost:20128/v1").replace(/\/$/, "");

  if (
    (process.env.RUNNING_IN_DOCKER === "true" || process.env.DOCKER_CONTAINER === "true") &&
    (baseUrl.includes("localhost") || baseUrl.includes("127.0.0.1"))
  ) {
    baseUrl = baseUrl.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal");
  }

  let model = config.model || process.env.LLM_MODEL || "wombo";
  if (model.toLowerCase().includes("wombo")) {
    model = "wombo";
  }

  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages,
      tools: RECON_TOOLS_SCHEMA,
      stream: true,
      temperature: 0.2,
    }),
  });

  if (!res.ok || !res.body) {
    const errText = await res.text().catch(() => "");
    throw new Error(`9router LLM error [${res.status}]: ${errText}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();

  let accumulatedContent = "";
  const toolCallsMap = new Map<number, { id: string; name: string; argsString: string }>();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const chunk = decoder.decode(value);
    const lines = chunk.split("\n");

    for (const line of lines) {
      if (!line.startsWith("data: ") || line.includes("[DONE]")) continue;

      try {
        const json = JSON.parse(line.slice(6));
        const delta = json.choices?.[0]?.delta;
        if (!delta) continue;

        if (delta.content) {
          accumulatedContent += delta.content;
          onContentChunk?.(delta.content);
        }

        if (delta.tool_calls && Array.isArray(delta.tool_calls)) {
          for (const tc of delta.tool_calls) {
            const idx = tc.index ?? 0;
            const existing = toolCallsMap.get(idx) || { id: "", name: "", argsString: "" };
            if (tc.id) existing.id = tc.id;
            if (tc.function?.name) existing.name = tc.function.name;
            if (tc.function?.arguments) existing.argsString += tc.function.arguments;
            toolCallsMap.set(idx, existing);
          }
        }
      } catch {}
    }
  }

  const toolCalls: Array<{ id: string; name: string; arguments: any }> = [];
  for (const item of toolCallsMap.values()) {
    let parsedArgs = {};
    try {
      parsedArgs = JSON.parse(item.argsString || "{}");
    } catch {
      parsedArgs = {};
    }
    toolCalls.push({
      id: item.id || `tc_${Date.now()}`,
      name: item.name,
      arguments: parsedArgs,
    });
  }

  return {
    content: accumulatedContent,
    toolCalls,
  };
}
