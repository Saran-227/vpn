"""
Asim Integration Adapter

This module is a placeholder for integrating Asim's
packet/flow feature extraction module with the
Security Assessment Engine.

IMPORTANT:
Asim's final feature names and output format are not
available yet.

Therefore, this file must be updated once his final
feature extraction schema is provided.

The core Security Assessment Engine should NOT need
to be rewritten.
"""

from typing import Dict, Any

from app.input_adapter import normalize_features


def convert_asim_output(
    asim_output: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convert Asim's future feature-extraction output into
    the standardized feature format expected by the
    Security Assessment Engine.

    Args:
        asim_output:
            Placeholder for the actual output generated
            by Asim's feature extraction module.

    Returns:
        Standardized network feature dictionary.

    IMPORTANT:
        The mappings below are temporary examples only.
        They MUST be updated when Asim provides his
        final feature schema.
    """

    # =====================================================
    # TODO: UPDATE THESE MAPPINGS
    # =====================================================
    #
    # Example:
    #
    # If Asim eventually provides:
    #
    #     "total_packets"
    #
    # while our engine expects:
    #
    #     "packet_count"
    #
    # then the mapping would become:
    #
    #     "packet_count": asim_output.get("total_packets", 0)
    #
    # Do NOT assume these names are final.
    # =====================================================

    temporary_mapping = {
        "flow_duration": asim_output.get(
            "flow_duration",
            0.0
        ),

        "packet_count": asim_output.get(
            "packet_count",
            0
        ),

        "bytes_sent": asim_output.get(
            "bytes_sent",
            0
        ),

        "bytes_received": asim_output.get(
            "bytes_received",
            0
        ),

        "avg_packet_size": asim_output.get(
            "avg_packet_size",
            0.0
        ),

        "packets_per_second": asim_output.get(
            "packets_per_second",
            0.0
        ),

        "bytes_per_second": asim_output.get(
            "bytes_per_second",
            0.0
        ),

        "tcp_connections": asim_output.get(
            "tcp_connections",
            0
        ),

        "udp_connections": asim_output.get(
            "udp_connections",
            0
        )
    }

    return normalize_features(
        temporary_mapping
    )


def assess_asim_features(
    asim_output: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function showing how Asim's output
    will eventually reach the Security Assessment Engine.

    This is currently a placeholder integration flow.
    """

    standardized_features = convert_asim_output(
        asim_output
    )

    return standardized_features