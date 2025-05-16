@echo off
echo ===================================================
echo Instalando Sistema de Comunicação Segura
echo ===================================================

:: Verificar se Python está instalado
python --version 2>NUL
if errorlevel 1 (
    echo Erro: Python não encontrado. Por favor, instale o Python 3.9 ou superior.
    echo Visite https://www.python.org/downloads/
    exit /b 1
)

:: Criar ambiente virtual (opcional)
echo.
echo [1/4] Criando ambiente virtual...
if not exist venv\ (
    python -m venv venv
) else (
    echo Ambiente virtual já existe.
)

:: Ativar ambiente virtual
echo.
echo [2/4] Ativando ambiente virtual...
call venv\Scripts\activate.bat

:: Instalar dependências
echo.
echo [3/4] Instalando dependências...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

:: Instalar o pacote em modo de desenvolvimento
echo.
echo [4/4] Instalando o pacote em modo de desenvolvimento...
python -m pip install -e .

echo.
echo ===================================================
echo Instalação concluída com sucesso!
echo.
echo Execute os seguintes comandos para usar o sistema:
echo.
echo - Servidor: python -m server.server
echo - Cliente:  python -m client.client
echo.
echo Ou teste o benchmark: python -m benchmark.performance_test
echo ===================================================
echo.

:: Manter a janela aberta
pause 