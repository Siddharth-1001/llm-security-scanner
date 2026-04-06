import openai

SYSTEM_PROMPT = "You are a helpful assistant. Answer questions accurately."


def chat_with_user(text: str) -> str:
    # SAFE: System prompt is static, user input only in user role
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        max_tokens=1000,
    )
    return response.choices[0].message.content
