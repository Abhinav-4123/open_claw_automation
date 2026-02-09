"""
Base Agent - Foundation for all OpenClaw agents
"""
import os
import json
import uuid
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import google.generativeai as genai

from memory.database import get_memory, Memory


class Tool:
    """Represents a tool that an agent can use"""

    def __init__(self, name: str, description: str, func: Callable, parameters: Dict):
        self.name = name
        self.description = description
        self.func = func
        self.parameters = parameters

    def to_gemini_format(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }

    async def execute(self, **kwargs) -> str:
        if asyncio.iscoroutinefunction(self.func):
            return await self.func(**kwargs)
        return self.func(**kwargs)


class BaseAgent(ABC):
    """
    Base class for all OpenClaw agents.
    Each agent has:
    - A role/persona
    - Access to tools
    - Shared memory
    - Ability to spawn child agents
    """

    def __init__(
        self,
        agent_id: str = None,
        role: str = "Agent",
        parent_id: str = None
    ):
        self.agent_id = agent_id or str(uuid.uuid4())[:8]
        self.role = role
        self.parent_id = parent_id
        self.memory = get_memory()
        self.tools: List[Tool] = []
        self.conversation_history = []
        self.max_iterations = 20

        # Initialize Gemini
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel(
            model_name=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
            system_instruction=self.get_system_prompt()
        )

        # Register in shared memory
        self.memory.register_agent(
            agent_id=self.agent_id,
            role=self.role,
            instructions=self.get_system_prompt(),
            parent_id=parent_id
        )

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Define the agent's persona and capabilities"""
        pass

    @abstractmethod
    def get_tools(self) -> List[Tool]:
        """Define tools available to this agent"""
        pass

    def add_tool(self, tool: Tool):
        self.tools.append(tool)

    async def think(self, task: str) -> Dict[str, Any]:
        """
        Main reasoning loop.
        Sends task to LLM, executes tool calls, repeats until done.
        """
        self.tools = self.get_tools()
        tool_configs = [t.to_gemini_format() for t in self.tools]

        messages = [{"role": "user", "parts": [task]}]
        iteration = 0
        final_result = None

        while iteration < self.max_iterations:
            iteration += 1

            # Call Gemini
            response = self.model.generate_content(
                messages,
                tools=tool_configs if tool_configs else None
            )

            # Check for function calls
            function_calls = []
            text_response = ""

            for part in response.parts:
                if hasattr(part, "function_call") and part.function_call:
                    function_calls.append(part.function_call)
                elif hasattr(part, "text") and part.text:
                    text_response += part.text

            # If no function calls, we're done
            if not function_calls:
                final_result = text_response
                break

            # Execute function calls
            function_responses = []
            for fc in function_calls:
                tool = next((t for t in self.tools if t.name == fc.name), None)
                if tool:
                    try:
                        result = await tool.execute(**dict(fc.args))
                        function_responses.append({
                            "name": fc.name,
                            "response": {"result": str(result)}
                        })
                    except Exception as e:
                        function_responses.append({
                            "name": fc.name,
                            "response": {"error": str(e)}
                        })

            # Add to conversation
            messages.append({"role": "model", "parts": response.parts})
            messages.append({
                "role": "user",
                "parts": [{"function_response": fr} for fr in function_responses]
            })

        # Update status
        self.memory.update_agent_status(
            self.agent_id,
            "completed",
            {"result": final_result, "iterations": iteration}
        )

        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "result": final_result,
            "iterations": iteration
        }

    async def run(self, task: str) -> Dict[str, Any]:
        """Execute the agent's task"""
        try:
            result = await self.think(task)
            return result
        except Exception as e:
            self.memory.update_agent_status(self.agent_id, "failed", {"error": str(e)})
            raise


class AgentSpawner:
    """
    The God Tool - Creates new agents dynamically
    """

    def __init__(self):
        self.memory = get_memory()
        self.active_agents: Dict[str, BaseAgent] = {}

    async def spawn(
        self,
        role: str,
        agent_class: type,
        parent_id: str = None,
        **kwargs
    ) -> BaseAgent:
        """Spawn a new agent"""
        agent = agent_class(
            role=role,
            parent_id=parent_id,
            **kwargs
        )
        self.active_agents[agent.agent_id] = agent
        return agent

    async def spawn_and_run(
        self,
        role: str,
        agent_class: type,
        task: str,
        parent_id: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Spawn an agent and immediately run a task"""
        agent = await self.spawn(role, agent_class, parent_id, **kwargs)
        result = await agent.run(task)
        return result

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        return self.active_agents.get(agent_id)

    def list_active_agents(self) -> List[str]:
        return list(self.active_agents.keys())


# Global spawner instance
spawner = AgentSpawner()
