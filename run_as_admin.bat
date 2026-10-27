@echo off
rem Legacy elevation launcher is disabled for the S1 read-only release.
echo Losshound S1 uses non-administrator, bounded diagnostic sessions.
echo Run the reviewed project environment with: python -m losshound --cli
exit /b 2
