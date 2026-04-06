import os

import openai

API_KEY = os.environ.get("SECRET_API_KEY")


def process_user_data(name: str, ssn: str, email: str) -> str:
    # VULNERABLE: PII passed directly to LLM
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "user",
                "content": f"Process this user: name={name}, ssn={ssn}, email={email}",
            }
        ],
    )
    return response.choices[0].message.content


def debug_prompt(user_input: str) -> dict:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"SECRET INSTRUCTIONS: API_KEY={API_KEY}"},
            {"role": "user", "content": user_input},
        ],
    )
    # VULNERABLE: System prompt exposed in response
    return {
        "response": response.choices[0].message.content,
        "system_prompt": f"SECRET INSTRUCTIONS: API_KEY={API_KEY}",
    }
