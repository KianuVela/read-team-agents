from dotenv import load_dotenv
import os

from red_team_agents.crew import RedTeamAgents

# Deterministic An alyst validation
from red_team_agents.post_processing.analyst_findings_post_processor import (
    AnalystFindingsPostProcessor,
)

# Deterministic Compliance validation
from red_team_agents.post_processing.compliance_mapping_post_processor import (
    ComplianceMappingPostProcessor,
)


load_dotenv()

def run():

    with open(
        "outputs/discovery/openapi_inventory.json",
        "r",
        encoding="utf-8"
    ) as f:
        openapi_inventory = f.read()

    with open(
        "reports/attack_surface_inventory.md",
        "r",
        encoding="utf-8"
    ) as f:
        attack_surface_inventory = f.read()

    with open(
        "reports/shadow_api_detection_report.md",
        "r",
        encoding="utf-8"
    ) as f:
        shadow_api_report = f.read()

    with open(
        "reports/threat_modeling.md",
        "r",
        encoding="utf-8"
    ) as f:
        threat_modeling_report = f.read()

    with open(
        "reports/test_planning_report.md",
        "r",
        encoding="utf-8"
    ) as f:
        test_planning_report = f.read()

    print("TARGET_URL =", os.getenv("TARGET_URL"))
    print("TARGET_HOST =", os.getenv("TARGET_HOST"))
    print("CRAPI_BASE_URL =", os.getenv("CRAPI_BASE_URL"))


    inputs = {
        "target_url": os.getenv("TARGET_URL"),
        "target_host": os.getenv("TARGET_HOST"),
        "execution_target_url": os.getenv(
            "EXECUTION_TARGET_URL"
        ),
        "openapi_url": os.getenv("OPENAPI_URL"),
        
        "openapi_inventory": openapi_inventory,
        "attack_surface_inventory": attack_surface_inventory,
        "shadow_api_report": shadow_api_report,
        "threat_modeling_report": threat_modeling_report,
        "test_planning_report": test_planning_report,


        "authentication_context_file": "outputs/execution/authentication_context.json",
        "object_context_file": "outputs/execution/object_context.json",
        "test_plan_file": "reports/test_planning_report.md",

        #"token_user_a": os.getenv("TOKEN_USER_A", ""),
        #"token_user_b": os.getenv("TOKEN_USER_B", ""),
        #"token_admin": os.getenv("TOKEN_ADMIN", ""),
        #"token_mechanic": os.getenv("TOKEN_MECHANIC", ""),
        #"token_management": os.getenv("TOKEN_MANAGEMENT", "")
    
    }

    #RedTeamAgents().crew().kickoff(
        #inputs=inputs
    #)

    # ============================================================

    # teste para correr apenas o agente openapi
    #RedTeamAgents().openapi_test_crew().kickoff(
        #inputs=inputs
    #)

    # ============================================================

    # Teste para correr o agente de attcak surface apenas com as 4 tools + 2 Deterministicas no shadow_api_detetction e api_operation
    #RedTeamAgents().attack_surface_test_crew().kickoff(
       # inputs=inputs
    #)

    # ============================================================

    # Teste para correr o agent shadow api
    #RedTeamAgents().shadow_api_test_crew().kickoff(
        #inputs=inputs
    #)

    # ============================================================

    # Teste para correr o agent de threat modeling
    #RedTeamAgents().threat_modeling_test_crew().kickoff(
        #inputs=inputs
    #)

    # ============================================================

    # Teste para correr o agent planeador
    #RedTeamAgents().test_planning_test_crew().kickoff(
        #inputs=inputs
   # )

   # ============================================================

    # Teste para correr o agent execution
    RedTeamAgents().execution_test_crew().kickoff(
        inputs=inputs
    )

    # ============================================================

    # Depois do Execution Agent terminar
    #post_processing_result = AnalystFindingsPostProcessor().run()

    #print("Deterministic findings validation completed.")
    #print(
        #"Mapping-ready findings:",
       # post_processing_result["metadata"]["mapping_ready_count"]
    #)

    # ============================================================

    # Teste para correr apenas o Analyst Agent
    #RedTeamAgents().analyst_test_crew().kickoff(
     #   inputs=inputs
    #)

    # ============================================================
    # Test Compliance Agent
    #RedTeamAgents().compliance_and_threat_mapping_crew().kickoff(
        #inputs=inputs
    #)

    #compliance_result = (ComplianceMappingPostProcessor().run())

    #print(
        #"Deterministic Compliance validation completed."
    #)

    #print(
        #"Validated compliance mappings:",
        #compliance_result[
            #"mapping_summary"
        #]["mapping_ready_count"]
    #)


if __name__ == "__main__":
    run()