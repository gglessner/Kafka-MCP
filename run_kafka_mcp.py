#!/usr/bin/env python3
"""
Kafka-MCP Server Entry Point

A pure-Python Kafka wire protocol MCP server for AI-driven broker
interaction and security testing. No external Kafka client dependencies.

Run this script to start the MCP server:
    python run_kafka_mcp.py

Or configure in .cursor/mcp.json:
    {
        "mcpServers": {
            "kafka-mcp": {
                "command": "python",
                "args": ["run_kafka_mcp.py"],
                "cwd": "${workspaceFolder}"
            }
        }
    }
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kafka_mcp.server import main

if __name__ == "__main__":
    main()
