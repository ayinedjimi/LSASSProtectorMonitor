@echo off
REM LSASSProtectorMonitor - Script de compilation
REM Ayi NEDJIMI Consultants

echo ====================================
echo LSASSProtectorMonitor - Compilation
echo Ayi NEDJIMI Consultants
echo ====================================
echo.

where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Environnement Visual Studio non detecte.
    echo Recherche de vcvarsall.bat...

    set "VCVARSALL="
    for %%e in (Enterprise Professional Community BuildTools) do (
        for %%v in (2022 2019 2017) do (
            if exist "C:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VCVARSALL=C:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvarsall.bat"
                goto :found
            )
            if exist "C:\Program Files (x86)\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvarsall.bat"
                goto :found
            )
        )
    )

    :found
    if defined VCVARSALL (
        echo Initialisation: %VCVARSALL%
        call "%VCVARSALL%" x64
    ) else (
        echo ERREUR: Visual Studio non trouve.
        echo Installez Visual Studio 2017 ou plus recent avec les outils C++.
        pause
        exit /b 1
    )
)

echo.
echo Compilation de LSASSProtectorMonitor.cpp...
cl.exe /EHsc /O2 /W3 /std:c++17 ^
    /D UNICODE /D _UNICODE ^
    LSASSProtectorMonitor.cpp ^
    /link ^
    psapi.lib ^
    wevtapi.lib ^
    comctl32.lib ^
    /OUT:LSASSProtectorMonitor.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ====================================
    echo Compilation reussie !
    echo Executable: LSASSProtectorMonitor.exe
    echo ====================================
    echo.

    if exist LSASSProtectorMonitor.obj del LSASSProtectorMonitor.obj

    echo ATTENTION: Cet outil necessite des privileges administrateur
    echo pour un monitoring optimal.
    echo.
    echo Voulez-vous executer LSASSProtectorMonitor maintenant ? (O/N)
    choice /C ON /N /M "Choix: "
    if errorlevel 2 goto :end
    if errorlevel 1 (
        echo.
        echo Lancement de LSASSProtectorMonitor...
        start LSASSProtectorMonitor.exe
    )
) else (
    echo.
    echo ====================================
    echo ERREUR lors de la compilation.
    echo ====================================
    pause
    exit /b 1
)

:end
echo.
pause
