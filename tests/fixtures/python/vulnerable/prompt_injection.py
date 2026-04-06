import openai


def chat_with_user(user_message: str) -> str:
    # VULNERABLE: Direct user input in system prompt
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": f"You are a helpful assistant. User said: {user_message}",
            },
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content


def generate_response(user_input: str) -> str:
    # VULNERABLE: String concatenation of user input into prompt
    system_prompt = "You are an AI assistant. " + user_input
    response = openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "system", "content": system_prompt}]
    )
    return response.choices[0].message.content
