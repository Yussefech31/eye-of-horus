@echo off
echo ===================================================
echo     Eye of Horus - Project Startup Script
echo ===================================================
echo.

echo [1/5] Starting Docker Services (MongoDB, Kafka, Zookeeper)...
docker-compose up -d
echo Waiting for services to initialize...
timeout /t 5 >nul
echo.

echo [2/5] Starting Scraper Orchestrator...
start "Scraper Orchestrator" cmd /k "cd /d %~dp0 && venv\Scripts\activate && python scraper/orchestrator.py"

echo [3/5] Starting Broker Consumer (raw-osint -> MongoDB)...
start "Broker Consumer" cmd /k "cd /d %~dp0 && venv\Scripts\activate && python broker/consumer.py"

echo [4/5] Starting Threat Processor (scoring + alerts)...
start "Threat Processor" cmd /k "cd /d %~dp0 && venv\Scripts\activate && python spark/threat_processor_basic.py"

echo [5/5] Starting Streamlit Dashboard...
start "Streamlit Dashboard" cmd /k "cd /d %~dp0 && venv\Scripts\activate && streamlit run dashboard/app.py"

echo.
echo ===================================================
echo All services have been launched in separate windows!
echo.
echo   Scraper Orchestrator  - collects OSINT data
echo   Broker Consumer       - persists raw data to MongoDB
echo   Threat Processor      - scores and generates alerts
echo   Streamlit Dashboard   - http://localhost:8501
echo.
echo You can close this window now.
echo ===================================================
pause
