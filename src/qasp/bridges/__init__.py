"""Protocol interoperability bridges.

This module provides bridges to other agent communication protocols:
- MCP (Model Context Protocol) bridge
- A2A (Agent-to-Agent) bridge
"""

from qasp.bridges.a2a_bridge import (
    QASP_EXTENSION_URI,
    QASP_TOKEN_METADATA_KEY,
    A2ABridge,
    A2ATaskState,
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    DelegationRecord,
    QASPAgentCard,
    QASPExtension,
    SkillCapabilityMapping,
    TaskSessionMapping,
    TaskState,
    check_connection_for_task,
    create_delegation_token,
    create_qasp_agent_extension,
    extract_qasp_extension,
    map_capability_to_skill,
    map_skill_to_capability,
)

__all__ = [
    "QASP_EXTENSION_URI",
    "QASP_TOKEN_METADATA_KEY",
    "A2ABridge",
    "A2ATaskState",
    "AgentCapabilities",
    "AgentCard",
    "AgentSkill",
    "DelegationRecord",
    "QASPAgentCard",
    "QASPExtension",
    "SkillCapabilityMapping",
    "TaskSessionMapping",
    "TaskState",
    "a2a_bridge",
    "check_connection_for_task",
    "create_delegation_token",
    "create_qasp_agent_extension",
    "extract_qasp_extension",
    "map_capability_to_skill",
    "map_skill_to_capability",
    "mcp_bridge",
]
