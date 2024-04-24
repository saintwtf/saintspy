@echo off
color 05
echo Made with love by @saintlf
echo.
set /p confirm=Are you sure you want to run this file? (y/n): 
if /i "%confirm%" neq "y" exit
echo.
echo Running...
start cmd /k python main/main.py
