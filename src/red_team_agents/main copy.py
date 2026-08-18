#!/usr/bin/env python
import sys
import os
import warnings

from datetime import datetime

from red_team_agents.crew import RedTeamAgents

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# reates output directory if it doesn't exist
os.makedirs('output', exist_ok=True)

module_name = "report"

def run():
    """
    Run the crew.
    """

    print("\n" + "=" * 60)
    print("🔍 STARTING LAYER 1: DISCOVERY & CONTEXTUALIZATION")
    print("=" * 60 + "\n")

inputs = {
    'requirements': 'requirements',
    'module_name': 'module_name',
    'class_name': 'class_name',
    'current_year': str(datetime.now().year)
}

results = RedTeamAgents().crew().kickoff(inputs=inputs)

# 9. Processing and showing results 
print("\n" + "=" * 60)
print("📋 ANAYSIS RESULTS")
print("=" * 60)
print(f"{results}\n")

if __name__ == "__main__":
    run()