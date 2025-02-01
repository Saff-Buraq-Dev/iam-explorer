from typing import Dict, List
import logging

logging.basicConfig(level=logging.INFO)


class IAMGraph:
    def __init__(self):
        """Initialize an empty IAM graph using an adjacency list."""
        self.graph = {}

    def add_node(self, node: str):
        """Add a node (IAM entity) to the graph."""
        if node not in self.graph:
            self.graph[node] = []

    def add_edge(self, source: str, target: str):
        """Add an edge between IAM entities (relationship)."""
        if source in self.graph:
            self.graph[source].append(target)
        else:
            self.graph[source] = [target]

    def build_graph(self, iam_data: Dict[str, List[Dict]]):
        """Construct the IAM graph from fetched data."""
        logging.info("Building IAM relationship graph...")

        # Add users and their group memberships
        for user in iam_data["users"]:
            user_name = f"User:{user['UserName']}"
            self.add_node(user_name)

        # Add roles
        for role in iam_data["roles"]:
            role_name = f"Role:{role['RoleName']}"
            self.add_node(role_name)

        # Add groups
        for group in iam_data["groups"]:
            group_name = f"Group:{group['GroupName']}"
            self.add_node(group_name)

        # Add policies
        for policy in iam_data["policies"]:
            policy_name = f"Policy:{policy['PolicyName']}"
            self.add_node(policy_name)

    def get_graph(self):
        """Return the constructed IAM graph."""
        return self.graph
