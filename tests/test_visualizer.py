"""
Tests for the visualizer module.
"""

import pytest
from unittest.mock import Mock, patch
import networkx as nx
import tempfile
import os

from iam_explorer.visualizer import GraphVisualizer
from iam_explorer.models import IAMUser, IAMRole, IAMGroup, IAMPolicy


class TestGraphVisualizer:
    """Test cases for GraphVisualizer class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create a sample graph
        self.graph = nx.DiGraph()

        # Add sample nodes
        user = IAMUser(name="alice", user_id="AIDACKCEVSQ6C2EXAMPLE", arn="arn:aws:iam::123456789012:user/alice")
        self.graph.add_node("alice", type="user", data=user)

        role = IAMRole(
            name="test-role",
            role_id="AROA123456789EXAMPLE",
            arn="arn:aws:iam::123456789012:role/test-role",
            trust_policy={},
        )
        self.graph.add_node("test-role", type="role", data=role)

        group = IAMGroup(
            name="developers", group_id="AGPA123456789EXAMPLE", arn="arn:aws:iam::123456789012:group/developers"
        )
        self.graph.add_node("developers", type="group", data=group)

        policy = IAMPolicy(
            name="TestPolicy",
            policy_id="ANPA123456789EXAMPLE",
            arn="arn:aws:iam::123456789012:policy/TestPolicy",
            policy_document={},
        )
        self.graph.add_node("TestPolicy", type="policy", data=policy)

        # Add sample edges
        self.graph.add_edge("alice", "developers", type="member_of")
        self.graph.add_edge("alice", "TestPolicy", type="attached_policy")
        self.graph.add_edge("alice", "test-role", type="can_assume")

        self.visualizer = GraphVisualizer(self.graph)

    def test_visualizer_initialization(self):
        """Test GraphVisualizer initialization."""
        visualizer = GraphVisualizer(self.graph)
        assert visualizer.graph == self.graph
        assert visualizer.colors is not None
        assert visualizer.shapes is not None

    def test_get_node_color_user(self):
        """Test getting node color for user."""
        color = self.visualizer._get_node_color("user")
        assert color == self.visualizer.colors["user"]

    def test_get_node_color_unknown(self):
        """Test getting node color for unknown type."""
        color = self.visualizer._get_node_color("unknown")
        assert color == self.visualizer.colors["default"]

    def test_get_node_shape_role(self):
        """Test getting node shape for role."""
        shape = self.visualizer._get_node_shape("role")
        assert shape == self.visualizer.shapes["role"]

    def test_get_node_shape_unknown(self):
        """Test getting node shape for unknown type."""
        shape = self.visualizer._get_node_shape("unknown")
        assert shape == self.visualizer.shapes["default"]

    def test_get_edge_style_can_assume(self):
        """Test getting edge style for can_assume relationship."""
        style = self.visualizer._get_edge_style("can_assume")
        assert "dashed" in style or "dotted" in style

    def test_get_edge_style_default(self):
        """Test getting edge style for default relationship."""
        style = self.visualizer._get_edge_style("unknown")
        assert "solid" in style

    def test_generate_dot_basic(self):
        """Test basic DOT generation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
            temp_file = f.name

        try:
            self.visualizer.generate_dot(temp_file)

            # Check that file was created
            assert os.path.exists(temp_file)

            # Check file content
            with open(temp_file, "r") as f:
                content = f.read()
                assert "digraph" in content
                assert "alice" in content
                assert "test-role" in content
                assert "developers" in content
                assert "TestPolicy" in content
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_generate_dot_with_filters(self):
        """Test DOT generation with entity filters."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
            temp_file = f.name

        try:
            self.visualizer.generate_dot(temp_file, filter_entities=["alice"])

            with open(temp_file, "r") as f:
                content = f.read()
                assert "alice" in content
                # Should include connected entities
                assert "developers" in content or "TestPolicy" in content
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_generate_dot_exclude_policies(self):
        """Test DOT generation excluding policies."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
            temp_file = f.name

        try:
            self.visualizer.generate_dot(temp_file, include_policies=False)

            with open(temp_file, "r") as f:
                content = f.read()
                assert "alice" in content
                assert "test-role" in content
                assert "developers" in content
                assert "TestPolicy" not in content
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch("matplotlib.pyplot.savefig")
    @patch("matplotlib.pyplot.figure")
    @patch("networkx.spring_layout")
    @patch("networkx.draw_networkx")
    def test_generate_matplotlib_basic(self, mock_draw, mock_layout, mock_figure, mock_savefig):
        """Test basic matplotlib generation."""
        mock_layout.return_value = {"alice": (0, 0), "test-role": (1, 1)}
        mock_fig = Mock()
        mock_figure.return_value = mock_fig

        self.visualizer.generate_matplotlib("test.png")

        mock_figure.assert_called_once()
        mock_layout.assert_called_once()
        mock_draw.assert_called_once()
        mock_savefig.assert_called_once_with("test.png", dpi=300, bbox_inches="tight")

    @patch("matplotlib.pyplot.savefig")
    @patch("matplotlib.pyplot.figure")
    @patch("networkx.spring_layout")
    @patch("networkx.draw_networkx")
    def test_generate_matplotlib_with_filters(self, mock_draw, mock_layout, mock_figure, mock_savefig):
        """Test matplotlib generation with filters."""
        mock_layout.return_value = {"alice": (0, 0)}
        mock_fig = Mock()
        mock_figure.return_value = mock_fig

        self.visualizer.generate_matplotlib("test.png", filter_entities=["alice"])

        mock_figure.assert_called_once()
        mock_layout.assert_called_once()
        mock_draw.assert_called_once()
        mock_savefig.assert_called_once()

    def test_filter_graph_by_entities(self):
        """Test filtering graph by specific entities."""
        filtered_graph = self.visualizer._filter_graph_by_entities(["alice"])

        # Should include alice and connected entities
        assert "alice" in filtered_graph.nodes

        # Should include some connected entities
        connected_entities = list(filtered_graph.nodes)
        assert len(connected_entities) >= 1

    def test_filter_graph_exclude_policies(self):
        """Test filtering graph to exclude policies."""
        filtered_graph = self.visualizer._filter_graph(include_policies=False)

        # Should include non-policy entities
        assert "alice" in filtered_graph.nodes
        assert "test-role" in filtered_graph.nodes
        assert "developers" in filtered_graph.nodes

        # Should exclude policies
        assert "TestPolicy" not in filtered_graph.nodes

    def test_filter_graph_include_policies(self):
        """Test filtering graph to include policies."""
        filtered_graph = self.visualizer._filter_graph(include_policies=True)

        # Should include all entities including policies
        assert "alice" in filtered_graph.nodes
        assert "test-role" in filtered_graph.nodes
        assert "developers" in filtered_graph.nodes
        assert "TestPolicy" in filtered_graph.nodes

    def test_escape_dot_string(self):
        """Test DOT string escaping."""
        test_string = 'test"string\\with/special<chars>'
        escaped = self.visualizer._escape_dot_string(test_string)

        # Should escape quotes and backslashes
        assert '"' not in escaped or '\\"' in escaped
        assert "\\" not in escaped or "\\\\" in escaped

    def test_get_subgraph_around_entity(self):
        """Test getting subgraph around specific entity."""
        subgraph = self.visualizer._get_subgraph_around_entity("alice", depth=1)

        # Should include alice
        assert "alice" in subgraph.nodes

        # Should include directly connected entities
        alice_neighbors = list(self.graph.neighbors("alice"))
        for neighbor in alice_neighbors:
            assert neighbor in subgraph.nodes

    def test_get_subgraph_around_entity_depth_2(self):
        """Test getting subgraph with depth 2."""
        subgraph = self.visualizer._get_subgraph_around_entity("alice", depth=2)

        # Should include alice
        assert "alice" in subgraph.nodes

        # Should include more entities at depth 2
        assert len(subgraph.nodes) >= len(self.visualizer._get_subgraph_around_entity("alice", depth=1).nodes)

    def test_generate_legend(self):
        """Test legend generation."""
        legend = self.visualizer._generate_legend()

        assert isinstance(legend, str)
        assert "user" in legend
        assert "role" in legend
        assert "group" in legend
        assert "policy" in legend

    def test_get_graph_statistics(self):
        """Test getting graph statistics."""
        stats = self.visualizer.get_graph_statistics()

        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert "node_types" in stats
        assert "edge_types" in stats

        assert stats["total_nodes"] == len(self.graph.nodes)
        assert stats["total_edges"] == len(self.graph.edges)
        assert isinstance(stats["node_types"], dict)
        assert isinstance(stats["edge_types"], dict)

    def test_validate_output_format(self):
        """Test output format validation."""
        # Valid formats should not raise exceptions
        self.visualizer._validate_output_format("dot")
        self.visualizer._validate_output_format("png")
        self.visualizer._validate_output_format("svg")

        # Invalid format should raise exception
        with pytest.raises(ValueError):
            self.visualizer._validate_output_format("invalid")

    def test_empty_graph_handling(self):
        """Test handling of empty graph."""
        empty_graph = nx.DiGraph()
        visualizer = GraphVisualizer(empty_graph)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
            temp_file = f.name

        try:
            # Should handle empty graph gracefully
            visualizer.generate_dot(temp_file)

            with open(temp_file, "r") as f:
                content = f.read()
                assert "digraph" in content
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_large_graph_handling(self):
        """Test handling of large graphs."""
        # Create a larger graph
        large_graph = nx.DiGraph()

        # Add many nodes
        for i in range(100):
            user = IAMUser(f"user{i}", f"id{i}", f"arn{i}")
            large_graph.add_node(f"user{i}", type="user", data=user)

        # Add many edges
        for i in range(99):
            large_graph.add_edge(f"user{i}", f"user{i + 1}", type="test")

        visualizer = GraphVisualizer(large_graph)

        # Should handle large graph without errors
        stats = visualizer.get_graph_statistics()
        assert stats["total_nodes"] == 100
        assert stats["total_edges"] == 99
