"""
IAM Explorer - A CLI tool to visualize AWS IAM relationships and answer permission queries.
"""

__version__ = "0.2.0"
__author__ = "Safouene Gharbi"
__email__ = "gharbi.safwen@hotmail.com"

from .models import IAMUser, IAMRole, IAMGroup, IAMPolicy, IAMGraph
from .fetcher import IAMFetcher
from .graph_builder import GraphBuilder
from .query_engine import QueryEngine
from .visualizer import GraphVisualizer

__all__ = [
    "IAMUser",
    "IAMRole",
    "IAMGroup",
    "IAMPolicy",
    "IAMGraph",
    "IAMFetcher",
    "GraphBuilder",
    "QueryEngine",
    "GraphVisualizer",
]
