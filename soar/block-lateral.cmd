@echo off
setlocal enableextensions enabledelayedexpansion

:: ==============================================================================
:: Wazuh Active Response Windows Bridge for Lateral Movement Containment
:: Target: C:\Program Files (x86)\ossec-agent\active-response\bin\block-lateral.cmd
:: ==============================================================================

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\SOC_Lateral_Defense\isolate_attacker.ps1" %*
