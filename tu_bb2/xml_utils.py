"""XML parsing utilities for extracting content from XML tags and formatting messages."""

from __future__ import annotations

import re
from typing import Any

from inspect_ai.model import ChatMessage


def _process_match_content(content_str: str) -> str:
    """Helper to strip whitespace and then any leading '*'.

    These characters come up since we are parsing MD.
    """
    stripped_content = content_str.strip()
    cleaned_further = stripped_content.strip("*")
    return cleaned_further


def truncate_output(
    output: str | None,
    head_lines: int = 30,
    tail_lines: int = 30,
) -> str | None:
    """Truncate output if it's too long, showing first and last n lines.

    Also truncate based on character count: treat every 100 chars as a line
    for truncation purposes (but do not actually add newlines).
    Character-based truncation takes precedence over line count.

    Args:
        output: The output string to truncate.
        head_lines: Number of lines to show at the start.
        tail_lines: Number of lines to show at the end.

    Returns:
        Truncated output string, or None if input was None.
    """
    if not output:
        return output

    # Character-based truncation takes precedence
    max_chars = (head_lines + tail_lines) * 100
    if len(output) > max_chars:
        head_chars = head_lines * 100
        tail_chars = tail_lines * 100
        truncated_count = len(output) - head_chars - tail_chars
        head = output[:head_chars]
        tail = output[-tail_chars:] if tail_chars > 0 else ""
        truncated_output = head
        truncated_output += f"\n\n... [TRUNCATED {truncated_count} chars] ...\n\n"
        truncated_output += tail
        return truncated_output

    # Otherwise, fall back to line-based truncation
    lines = output.split("\n")
    max_lines = head_lines + tail_lines
    if len(lines) <= max_lines:
        return output

    head = lines[:head_lines]
    tail = lines[-tail_lines:]
    truncated_count = len(lines) - head_lines - tail_lines
    truncated_output = "\n".join(head)
    truncated_output += f"\n\n... [TRUNCATED {truncated_count} lines] ...\n\n"
    truncated_output += "\n".join(tail)
    return truncated_output


def messages_to_xml(
    messages: list[ChatMessage],
    include_text: bool = True,
    include_outputs: bool = True,
    max_output_lines: int = 100,
) -> str:
    """Convert a list of chat messages to XML format.

    Args:
        messages: List of chat messages to convert.
        include_text: Whether to include text content in the XML.
        include_outputs: Whether to include tool outputs in the XML.
        max_output_lines: Maximum number of lines to include in tool outputs.

    Returns:
        XML string representation of the messages.
    """
    xml_str = ""

    step_num = 1
    i = 1

    while i < len(messages):
        message = messages[i]

        # Look for assistant messages
        if message.role == "assistant":
            xml_str += f"<step_{step_num}>\n"

            # Add assistant content
            xml_str += "<assistant>\n"

            # Add text content if present
            if include_text and message.content:
                for content_item in message.content:
                    if isinstance(content_item, str):
                        xml_str += f"<text>{content_item}</text>\n"
                    elif hasattr(content_item, "text") and content_item.text:  # type: ignore
                        xml_str += f"<text>{content_item.text}</text>\n"  # type: ignore

            # Add tool calls if present
            if message.tool_calls:
                for k, tool_call in enumerate(message.tool_calls):
                    xml_str += f"<tool_{k}>\n"
                    xml_str += f"<function>{tool_call.function}</function>\n"
                    xml_str += f"<arguments>{tool_call.arguments}</arguments>\n"
                    xml_str += f"</tool_{k}>\n"

            xml_str += "</assistant>\n"

            # Look for tool response messages and process all consecutive ones
            j = i + 1
            while j < len(messages) and messages[j].role == "tool":
                tool_response = messages[j]
                if not isinstance(tool_response.content, str):
                    raise ValueError(
                        f"Tool response content is not a string: {tool_response.content}"
                    )

                if max_output_lines:
                    output_str = truncate_output(
                        tool_response.content,
                        head_lines=max_output_lines // 2,
                        tail_lines=max_output_lines // 2,
                    )
                else:
                    output_str = tool_response.content

                if include_outputs:
                    xml_str += f"<tool_output_{j - (i + 1)}>{output_str}</tool_output_{j - (i + 1)}>\n"

                j += 1
            i = j - 1  # Set i to the last tool response message we processed

            xml_str += f"</step_{step_num}>\n"
            step_num += 1

        i += 1

    return xml_str


def extract_xml_tag(
    text: str, tag: str, exact_match: bool = False, last_match: bool = True
) -> str | None:
    """Extract content from an XML tag.

    Args:
        text: The text containing the XML.
        tag: The XML tag to extract content from.
        exact_match: Whether to require an exact tag match.
        last_match: If True, return the last match; otherwise return the first.

    Returns:
        The extracted tag content with whitespace stripped, or None if not found.
    """
    # First, try to match the exact tag
    regex = re.compile(rf"<{tag}>(.*?)</{tag}>", re.DOTALL | re.IGNORECASE)
    match = regex.search(text)
    if match and match.lastindex:
        index = match.lastindex if last_match else 1
        return _process_match_content(match.group(index))

    if exact_match:
        return None

    # If no exact match, try to match tags containing "tag"
    reasoning_regex = re.compile(
        rf"<[^>]*\b{tag}\b[^>]*>(.*?)</[^>]*\b{tag}\b[^>]*>",
        re.DOTALL | re.IGNORECASE,
    )
    match = reasoning_regex.search(text)
    if match and match.lastindex:
        index = match.lastindex if last_match else 1
        return _process_match_content(match.group(index))

    return None


def extract_int_from_xml_tag(
    text: str,
    tag: str,
    exact_match: bool = False,
    last_match: bool = True,
) -> int | None:
    """Extract content from an XML tag and convert it to an integer.

    First, it uses extract_xml_tag to get the cleaned string content.
    Then, it tries a direct int() conversion.
    If that fails (e.g., if the string is "Score: 1 point"), it searches
    for the first integer pattern (e.g., "123", "-45") within the string.

    Args:
        text: The text containing the XML.
        tag: The XML tag to extract content from.
        exact_match: Whether to require an exact tag match.
        last_match: If True, return the last match; otherwise return the first.

    Returns:
        The extracted integer, or None if not found or conversion fails.
    """
    content_str = extract_xml_tag(
        text, tag, exact_match=exact_match, last_match=last_match
    )

    if content_str is None:
        return None

    try:
        # int() can handle strings with leading/trailing whitespace, e.g., "  1\n"
        return int(content_str)
    except ValueError:
        # If direct conversion fails, try to find an integer pattern in the string.
        match_int = re.search(r"([-+]?\d+)", content_str)
        if match_int:
            try:
                return int(match_int.group(1))
            except ValueError:
                return None
        else:
            return None
