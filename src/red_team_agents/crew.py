from dotenv import load_dotenv
import os

from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import FileReadTool, FileWriterTool
# Tools

from red_team_agents.tools.openapi_discovery_tool import OpenAPIDiscoveryTool
from red_team_agents.tools.authentication_context_tool import AuthenticationContextTool
from red_team_agents.tools.object_discovery_tool import ObjectDiscoveryTool
from red_team_agents.tools.kali_mcp_tool import KaliMCPTool
from red_team_agents.tools.execution_controller_tool import (
    ExecutionControllerTool,
)

#from tools.kali_mcp_tool import KaliMCPTool

load_dotenv()

llm = LLM(
model=os.getenv("MODEL_NAME"),
temperature=float(os.getenv("OPENAI_TEMPERATURE", 0)
    )
)

@CrewBase
class RedTeamAgents():
    """API Security Assessment Crew"""

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"


    @agent
    def agent_attack_surface_discovery(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_attack_surface_discovery"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False,
            max_iter=50,
            max_execution_time=500,
            tools=[KaliMCPTool()]
        )

    @agent
    def agent_openapi_discovery(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_openapi_discovery"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False,
            max_iter=50,
            max_execution_time=500,
            tools=[OpenAPIDiscoveryTool()
            ]
        )

    @agent
    def agent_shadow_api_detection(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_shadow_api_detection"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False
        )

    @agent
    def agent_threat_modeling(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_threat_modeling"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False
        )

    @agent
    def agent_test_planning(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_test_planning"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False
        )

    @agent
    def agent_execution(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_execution"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False,
            tools=[
                AuthenticationContextTool(),
                ObjectDiscoveryTool(), 
                ExecutionControllerTool(),
                FileReadTool(),
                KaliMCPTool(),
                FileWriterTool()
            ]
        )

    @agent
    def agent_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_analyst"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False,
            tools=[
                FileReadTool()
            ]
        )

    @agent
    def agent_compliance_and_threat_mapping(self) -> Agent:
        return Agent(
            config=self.agents_config[
                "agent_compliance_and_threat_mapping"
            ],
            llm=llm,
            verbose=True,
            memory=True,
            cache=True,
            allow_delegation=False,
            tools=[FileReadTool()]
        )


    @task
    def attack_surface_discovery_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "attack_surface_discovery_task"
            ]
        )

    @task
    def openapi_discovery_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "openapi_discovery_task"
            ]
        )

    @task
    def shadow_api_detection_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "shadow_api_detection_task"
            ]
        )

    @task
    def threat_modeling_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "threat_modeling_task"
            ]
        )

    @task
    def test_planning_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "test_planning_task"
            ]
        )

    @task
    def execution_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "execution_task"
            ]
        )

    @task
    def analyst_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "analyst_task"
            ]
        )

    @task
    def compliance_and_threat_mapping_task(self) -> Task:
        return Task(
            config=self.tasks_config[
                "compliance_and_threat_mapping_task"
            ]
        )


    #@crew
    #def crew(self) -> Crew:

        #return Crew(
            #name="API Security Assessment Agent Team",

           # agents=self.agents,

            #tasks=self.tasks,

            #process=Process.sequential,

           # verbose=True,

           # memory=True
        #)

    # Testando apenas o agente openapi
    #@crew
    #def openapi_test_crew(self) -> Crew:

        #return Crew(
            #agents=[self.agent_openapi_discovery()],

            #tasks=[self.openapi_discovery_task()],

            #process=Process.sequential,

            #verbose=True
        #)

    # Testando o agente de attack surface que usa NMAP, GOBUSTER, CURL e Nikto
    #@crew
    #def attack_surface_test_crew(self) -> Crew:

        #return Crew(
            #agents=[self.agent_attack_surface_discovery()],

            #tasks=[self.attack_surface_discovery_task()],

            #process=Process.sequential,

            #verbose=True,

            #memory=True
    #)

    # Testando a deteção de Shadow APIs
    #@crew
    #def shadow_api_test_crew(self) -> Crew:

        #return Crew(
            #agents=[self.agent_shadow_api_detection()],

            #tasks=[self.shadow_api_detection_task()],

            #process=Process.sequential,

            #verbose=True,

            #memory=True
    #)

    # Testando o threat modeling para BOLA e BFLA
    #@crew
    #def threat_modeling_test_crew(self) -> Crew:

        #return Crew(
            #agents=[self.agent_threat_modeling()],

            #tasks=[self.threat_modeling_task()],

            #process=Process.sequential,

            #verbose=True,

            #memory=True
    #)

    # Testando o agente que fará o palno dos testes
    #@crew
    #def test_planning_test_crew(self) -> Crew:

        #return Crew(
            #agents=[self.agent_test_planning()],

            #tasks=[self.test_planning_task()],

            #process=Process.sequential,

            #verbose=True,

            #memory=True
    #)

    # Testando a o agente que fará a execução dos testes
    #@crew
   # def execution_test_crew(self) -> Crew:

        #return Crew(
         #   agents=[self.agent_execution()],
          #  tasks=[self.execution_task()],
          #  process=Process.sequential,
          #  verbose=True, 
           # memory=True
    #)

    # Testando apenas o Analyst Agent
    #@crew
    #def analyst_test_crew(self) -> Crew:

        #return Crew(
        #    agents=[self.agent_analyst()],
         #   tasks=[self.analyst_task()],
         #   process=Process.sequential,
          #  verbose=True,
          #  memory=True
    #)

    @crew
    def compliance_and_threat_mapping_crew(self) -> Crew:
        return Crew(
            agents=[self.agent_compliance_and_threat_mapping()],
            tasks=[self.compliance_and_threat_mapping_task()],
            process=Process.sequential,
            verbose=True,
            memory=True
        )


    

