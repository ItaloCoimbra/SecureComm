@echo off
setlocal
cd /d "%~dp0"

echo Instalando o prototipo experimental SecureComm.
echo O cliente usa E2EE; o relay armazena envelopes cifrados. Ainda nao auditado.

python --version >NUL 2>&1
if errorlevel 1 (
    echo Erro: instale Python 3.10 ou superior e adicione-o ao PATH.
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo Erro: Python 3.10 ou superior e necessario.
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 exit /b 1
)

".venv\Scripts\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo Erro: a .venv existente usa Python antigo. Crie outra com Python 3.10+.
    exit /b 1
)

".venv\Scripts\python.exe" -m pip install .
if errorlevel 1 exit /b 1

echo.
echo Instalacao concluida. Testes e ferramentas de desenvolvimento opcionais:
echo   .venv\Scripts\python.exe -m pip install -r requirements-dev.txt
echo   .venv\Scripts\python.exe -m pytest
echo Para consultar os comandos sem iniciar a rede:
echo   .venv\Scripts\securecomm-server.exe --help
echo   .venv\Scripts\securecomm-client.exe --help
echo Treinamento opcional:
echo   .venv\Scripts\python.exe -m pip install -r requirements-training.txt
endlocal
