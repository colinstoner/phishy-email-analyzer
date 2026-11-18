/**
 * Conversation Types
 * Provider-neutral types for multi-turn, tool-using model conversations.
 * They mirror the Anthropic Messages API shape, which both providers speak
 * natively (the Anthropic API directly, Bedrock via InvokeModel).
 */

import { TokenUsage } from '../../types';

/** A tool the model may call, defined with a JSON Schema for its input */
export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface TextBlock {
  type: 'text';
  text: string;
}

/** The model requesting a tool invocation */
export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

/** The result of a tool invocation, sent back to the model */
export interface ToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

export type ContentBlock = TextBlock | ToolUseBlock;
export type ContentBlockParam = TextBlock | ToolUseBlock | ToolResultBlock;

/**
 * A content block exactly as the API returned it. Assistant turns are replayed
 * from these, never from the typed view: `thinking` blocks carry a signature
 * bound to the conversation, so they must go back byte-for-byte or not at all.
 */
export type RawContentBlock = { type: string } & Record<string, unknown>;

export interface ConversationMessage {
  role: 'user' | 'assistant';
  content: string | Array<ContentBlockParam | RawContentBlock>;
}

export interface ConversationRequest {
  system?: string;
  messages: ConversationMessage[];
  tools?: ToolDefinition[];
  maxTokens?: number;
}

export interface ConversationResponse {
  /** Text and tool_use blocks, in model order (thinking blocks are not here) */
  content: ContentBlock[];
  /**
   * Every block of the assistant turn, unmodified, thinking included. Append
   * this — not `content` — when sending the turn back in a tool loop.
   */
  rawContent?: RawContentBlock[];
  /** 'end_turn', 'tool_use', 'max_tokens', 'refusal', ... */
  stopReason?: string;
  /** `stop_details.category` of a refusal. Informational; may be null. */
  refusalCategory?: string | null;
  usage?: TokenUsage;
}

/** Concatenated text of a response's text blocks */
export function responseText(response: ConversationResponse): string {
  return response.content
    .filter((block): block is TextBlock => block.type === 'text')
    .map(block => block.text)
    .join('\n');
}

/** The tool_use blocks of a response */
export function responseToolUses(response: ConversationResponse): ToolUseBlock[] {
  return response.content.filter((block): block is ToolUseBlock => block.type === 'tool_use');
}
