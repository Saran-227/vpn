@echo off
cd /d "%~dp0backend"
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
