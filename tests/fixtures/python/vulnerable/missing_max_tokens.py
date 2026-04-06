import anthropic
import openai


def get_completion(user_input: str) -> str:
    # VULNERABLE: No max_tokens specified - DoS risk
    response = openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content


client = anthropic.Anthropic()


def get_claude_response(prompt: str) -> str:
    # VULNERABLE: No max_tokens
    message = client.messages.create(
        model="claude-3-opus-20240229", messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text
