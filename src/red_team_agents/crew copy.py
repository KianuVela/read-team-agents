from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class RedTeamAgents():
    """RedTeamAgents crew"""

    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    @agent
    def agent_detective(self) -> Agent:
        return Agent(
            config=self.agents_config['agent_detective'], 
            verbose=True,
            max_retry_limits=5,
            timeout=30 , # O agente aguarda no máximo 30 segundos por uma resposta
            retry_backoff=10,  # Aumenta o tempo de espera entre cada tentativa de 10 segundos
            max_iter=50,  # Limita o agente a 50 iterações para encontrar vulnerabilidades
            max_execution_time=500,
            cache=True,  # Ativa o cache para armazenar as respostas de testes anteriores
            memory=True,  # Permite que o agente guarde informações de testes anteriores
            code_execution_mode='safe',
            allow_delegation=False,
            tools=[OpenAPI_tool, nikto_tool, nuclei_tool]
        )

    @agent
    def agent_architect(self) -> Agent:
        return Agent(
            config=self.agents_config['agent_architect'], # type: ignore[index]
            verbose=True
        )
    
    @agent
    def agent_inference(self) -> Agent:
        return Agent(
            config=self.agents_config['agent_inference'], # type: ignore[index]
            verbose=True
        )
    
    @agent
    def agent_validator(self) -> Agent:
        return Agent(
            config=self.agents_config['agent_validator'], # type: ignore[index]
            verbose=True
        )
    
    @agent
    def agent_reporter(self) -> Agent:
        return Agent(
            config=self.agents_config['agent_reporter'], # type: ignore[index]
            verbose=True
        )



    @task
    def detective_task(self) -> Task:
        return Task(
            config=self.tasks_config['detective_task'], 
        )

    @task
    def architect_task(self) -> Task:
        return Task(
            config=self.tasks_config['architect_task'], 
        )
    
    @task
    def inference_task(self) -> Task:
        return Task(
            config=self.tasks_config['inference_task'], 
        )
    
    @task
    def validator_task(self) -> Task:
        return Task(
            config=self.tasks_config['validator_task'], 
        )
       
    @task
    def reporter_task(self) -> Task:
        return Task(
            config=self.tasks_config['reporter_task'], 
            output_file='report.md'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the RedTeamAgents crew"""
   
        return Crew(
            name="🛡️ Complete API Security Assessment Team",
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
