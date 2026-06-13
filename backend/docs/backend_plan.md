# Backend Plan

## Week 1 Goal

Build the foundation of the SOAR Engine.

## Components

### main.py
Purpose:
Start FastAPI server

### parser.py
Purpose:
Extract data from incoming alerts

Input:
Raw JSON alert

Output:
Structured alert

### normalizer.py
Purpose:
Convert different alert formats into one standard format

Input:
Parsed alert

Output:
Normalized alert

## Flow

SIEM Alert
    ↓
FastAPI Endpoint
    ↓
Parser
    ↓
Normalizer
    ↓
Database