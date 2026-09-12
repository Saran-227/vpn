# Asim Integration

This directory contains the integration layer between
Asim's packet/flow feature extraction module and the
Security Assessment Engine.

## Current Status

Asim's final feature extraction schema is not available yet.

Therefore:

`asim_adapter_placeholder.py`

currently provides a temporary adapter.

## Data Flow

```text
Asim Feature Extractor
        ↓
asim_adapter_placeholder.py
        ↓
Standardized Features
        ↓
Security Assessment Engine
        ↓
Security Assessment Result