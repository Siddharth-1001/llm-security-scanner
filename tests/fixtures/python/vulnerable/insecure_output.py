import openai


def run_user_code(user_request: str) -> None:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Write Python code to: {user_request}"}],
    )
    code = response.choices[0].message.content
    # VULNERABLE: LLM output passed directly to eval
    eval(code)


def execute_llm_command(prompt: str) -> None:
    import subprocess

    response = openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "user", "content": prompt}]
    )
    cmd = response.choices[0].message.content
    # VULNERABLE: LLM output passed to subprocess
    subprocess.run(cmd, shell=True)
