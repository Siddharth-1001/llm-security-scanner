import openai

SYSTEM_PROMPT = "You are a helpful assistant. Answer questions accurately."


def chat_with_user(user_message: str) -> str:
    # SAFE: System prompt is static, user input only in user role
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        max_tokens=1000,
    )
    return response.choices[0].message.content
