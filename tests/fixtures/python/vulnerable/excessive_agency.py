import subprocess

from langchain.agents import AgentType, initialize_agent
from langchain.tools import Tool


def create_unrestricted_agent(llm):
    # VULNERABLE: Agent with unrestricted file system access
    tools = [
        Tool(
            name="ReadFile",
            func=lambda path: open(path).read(),
            description="Read any file from the filesystem",
        ),
        Tool(
            name="WriteFile",
            func=lambda args: open(args.split("|")[0], "w").write(args.split("|")[1]),
            description="Write to any file on the filesystem",
        ),
        Tool(
            name="ExecuteCode",
            func=lambda code: exec(code),  # VULNERABLE: exec in tool
            description="Execute arbitrary Python code",
        ),
        Tool(
            name="RunCommand",
            func=lambda cmd: (
                subprocess.run(cmd, shell=True, capture_output=True).stdout
            ),
            description="Run any shell command",
        ),
    ]
    # VULNERABLE: No human-in-the-loop for destructive actions
    agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
    return agent
