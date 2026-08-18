from abc import ABC, abstractmethod

from .execution_context import ExecutionContext


class ExecutionContextProvider(ABC):

    @abstractmethod
    def build_context(
        self,
        target_url: str,
        inventory_file: str,
    ) -> ExecutionContext:
        """
        Build and return a fully initialized execution context.
        """
        raise NotImplementedError