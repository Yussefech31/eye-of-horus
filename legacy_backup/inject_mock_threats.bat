@echo off
echo ===================================================
echo     Eye of Horus - Mock Threat Injector
echo ===================================================
echo.
echo Make sure your pipeline is already running!
echo.
pause

echo.
echo [1/1] Generating mock threats CONTINUOUSLY...
echo Press Ctrl+C to stop.
echo.
call venv\Scripts\activate
python scraper\mock_scraper.py
pause
