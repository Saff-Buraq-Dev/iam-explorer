"""
Graph visualization using Graphviz and matplotlib.
"""

import logging
from typing import Dict, List, Optional, Set
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import to_hex
import graphviz

from .models import IAMGraph

logger = logging.getLogger(__name__)


class GraphVisualizer:
    """Visualizes IAM graphs using various formats."""
    
    def __init__(self, graph: IAMGraph):
        """
        Initialize the visualizer.
        
        Args:
            graph: IAMGraph object to visualize
        """
        self.graph = graph
        self.colors = {
            'user': '#FF6B6B',      # Red
            'role': '#4ECDC4',      # Teal
            'group': '#45B7D1',     # Blue
            'policy': '#96CEB4',    # Green
            'service': '#FFEAA7'    # Yellow
        }
        self.edge_colors = {
            'attached_policy': '#2D3436',     # Dark gray
            'member_of': '#6C5CE7',           # Purple
            'can_assume': '#FD79A8',          # Pink
            'permission_boundary': '#E17055'   # Orange
        }
    
    def generate_dot(self, output_file: str, include_policies: bool = True, 
                    filter_entities: Optional[List[str]] = None):
        """
        Generate a DOT file for Graphviz visualization.
        
        Args:
            output_file: Path to output DOT file
            include_policies: Whether to include policy nodes
            filter_entities: List of entity names to include (None for all)
        """
        logger.info(f"Generating DOT file: {output_file}")
        
        dot = graphviz.Digraph(comment='IAM Relationships')
        dot.attr(rankdir='TB', size='12,8', dpi='300')
        
        # Configure node styles
        dot.attr('node', shape='box', style='rounded,filled', fontname='Arial')
        dot.attr('edge', fontname='Arial', fontsize='10')
        
        # Filter entities if specified
        entities_to_include = self._get_filtered_entities(filter_entities)
        
        # Add nodes
        self._add_dot_nodes(dot, entities_to_include, include_policies)
        
        # Add edges
        self._add_dot_edges(dot, entities_to_include, include_policies)
        
        # Save to file
        try:
            with open(output_file, 'w') as f:
                f.write(dot.source)
            logger.info(f"DOT file saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving DOT file: {e}")
            raise
    
    def generate_matplotlib(self, output_file: str, layout: str = 'spring',
                          include_policies: bool = True, 
                          filter_entities: Optional[List[str]] = None):
        """
        Generate a matplotlib visualization.
        
        Args:
            output_file: Path to output image file
            layout: Layout algorithm ('spring', 'circular', 'hierarchical')
            include_policies: Whether to include policy nodes
            filter_entities: List of entity names to include (None for all)
        """
        logger.info(f"Generating matplotlib visualization: {output_file}")
        
        # Create filtered subgraph
        subgraph = self._create_filtered_subgraph(filter_entities, include_policies)
        
        # Set up the plot
        plt.figure(figsize=(16, 12))
        
        # Choose layout
        if layout == 'spring':
            pos = nx.spring_layout(subgraph, k=3, iterations=50)
        elif layout == 'circular':
            pos = nx.circular_layout(subgraph)
        elif layout == 'hierarchical':
            pos = self._hierarchical_layout(subgraph)
        else:
            pos = nx.spring_layout(subgraph)
        
        # Draw nodes by type
        self._draw_matplotlib_nodes(subgraph, pos)
        
        # Draw edges by type
        self._draw_matplotlib_edges(subgraph, pos)
        
        # Add legend
        self._add_matplotlib_legend()
        
        # Configure plot
        plt.title("IAM Relationships Graph", fontsize=16, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        
        # Save
        try:
            plt.savefig(output_file, dpi=300, bbox_inches='tight', 
                       facecolor='white', edgecolor='none')
            logger.info(f"Matplotlib visualization saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving matplotlib visualization: {e}")
            raise
        finally:
            plt.close()
    
    def _get_filtered_entities(self, filter_entities: Optional[List[str]]) -> Set[str]:
        """Get set of entity ARNs to include based on filter."""
        if not filter_entities:
            return set(self.graph.graph.nodes())
        
        entities_to_include = set()
        
        for entity_name in filter_entities:
            entity = self.graph.get_entity_by_name(entity_name)
            if entity:
                entities_to_include.add(entity.arn)
                
                # Also include related entities
                for neighbor in self.graph.graph.neighbors(entity.arn):
                    entities_to_include.add(neighbor)
                
                # Include predecessors too
                for predecessor in self.graph.graph.predecessors(entity.arn):
                    entities_to_include.add(predecessor)
        
        return entities_to_include
    
    def _add_dot_nodes(self, dot: graphviz.Digraph, entities_to_include: Set[str], 
                      include_policies: bool):
        """Add nodes to DOT graph."""
        for node_id, node_data in self.graph.graph.nodes(data=True):
            if node_id not in entities_to_include:
                continue
            
            node_type = node_data.get('type', 'unknown')
            
            if not include_policies and node_type == 'policy':
                continue
            
            # Configure node appearance
            color = self.colors.get(node_type, '#CCCCCC')
            label = node_data.get('name', node_id.split('/')[-1])
            
            # Truncate long labels
            if len(label) > 20:
                label = label[:17] + '...'
            
            dot.node(node_id, label=label, fillcolor=color, 
                    tooltip=f"{node_type}: {node_data.get('name', '')}")
    
    def _add_dot_edges(self, dot: graphviz.Digraph, entities_to_include: Set[str], 
                      include_policies: bool):
        """Add edges to DOT graph."""
        for source, target, edge_data in self.graph.graph.edges(data=True):
            if source not in entities_to_include or target not in entities_to_include:
                continue
            
            # Skip policy edges if not including policies
            if not include_policies:
                source_type = self.graph.graph.nodes[source].get('type')
                target_type = self.graph.graph.nodes[target].get('type')
                if source_type == 'policy' or target_type == 'policy':
                    continue
            
            edge_type = edge_data.get('type', 'unknown')
            color = self.edge_colors.get(edge_type, '#666666')
            
            dot.edge(source, target, label=edge_type, color=color, 
                    tooltip=f"Relationship: {edge_type}")
    
    def _create_filtered_subgraph(self, filter_entities: Optional[List[str]], 
                                 include_policies: bool) -> nx.DiGraph:
        """Create a filtered subgraph for visualization."""
        entities_to_include = self._get_filtered_entities(filter_entities)
        
        # Create subgraph
        subgraph = self.graph.graph.subgraph(entities_to_include).copy()
        
        # Remove policy nodes if not including them
        if not include_policies:
            policy_nodes = [node for node, data in subgraph.nodes(data=True) 
                           if data.get('type') == 'policy']
            subgraph.remove_nodes_from(policy_nodes)
        
        return subgraph
    
    def _draw_matplotlib_nodes(self, graph: nx.DiGraph, pos: Dict):
        """Draw nodes in matplotlib."""
        for node_type in ['user', 'role', 'group', 'policy', 'service']:
            nodes = [node for node, data in graph.nodes(data=True) 
                    if data.get('type') == node_type]
            
            if nodes:
                nx.draw_networkx_nodes(graph, pos, nodelist=nodes,
                                     node_color=self.colors.get(node_type, '#CCCCCC'),
                                     node_size=1000, alpha=0.8)
        
        # Add labels
        labels = {node: data.get('name', node.split('/')[-1])[:15] 
                 for node, data in graph.nodes(data=True)}
        nx.draw_networkx_labels(graph, pos, labels, font_size=8, font_weight='bold')
    
    def _draw_matplotlib_edges(self, graph: nx.DiGraph, pos: Dict):
        """Draw edges in matplotlib."""
        for edge_type in ['attached_policy', 'member_of', 'can_assume', 'permission_boundary']:
            edges = [(u, v) for u, v, data in graph.edges(data=True) 
                    if data.get('type') == edge_type]
            
            if edges:
                nx.draw_networkx_edges(graph, pos, edgelist=edges,
                                     edge_color=self.edge_colors.get(edge_type, '#666666'),
                                     arrows=True, arrowsize=20, alpha=0.7,
                                     connectionstyle="arc3,rad=0.1")
    
    def _add_matplotlib_legend(self):
        """Add legend to matplotlib plot."""
        # Node legend
        node_patches = [mpatches.Patch(color=color, label=node_type.title()) 
                       for node_type, color in self.colors.items()]
        
        # Edge legend
        edge_patches = [mpatches.Patch(color=color, label=edge_type.replace('_', ' ').title()) 
                       for edge_type, color in self.edge_colors.items()]
        
        # Combine legends
        all_patches = node_patches + edge_patches
        plt.legend(handles=all_patches, loc='upper left', bbox_to_anchor=(1, 1))
    
    def _hierarchical_layout(self, graph: nx.DiGraph) -> Dict:
        """Create a hierarchical layout."""
        # Simple hierarchical layout based on node types
        pos = {}
        y_positions = {'user': 3, 'group': 2, 'role': 1, 'policy': 0}
        
        type_counts = {}
        for node, data in graph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            if node_type not in type_counts:
                type_counts[node_type] = 0
            
            y = y_positions.get(node_type, 0)
            x = type_counts[node_type] * 2
            pos[node] = (x, y)
            type_counts[node_type] += 1
        
        return pos
    
    def get_graph_stats(self) -> Dict[str, int]:
        """Get statistics about the graph."""
        stats = {
            'total_nodes': len(self.graph.graph.nodes),
            'total_edges': len(self.graph.graph.edges),
            'users': len(self.graph.users),
            'roles': len(self.graph.roles),
            'groups': len(self.graph.groups),
            'policies': len(self.graph.policies)
        }
        
        # Count edge types
        edge_types = {}
        for _, _, data in self.graph.graph.edges(data=True):
            edge_type = data.get('type', 'unknown')
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
        
        stats['edge_types'] = edge_types
        return stats
