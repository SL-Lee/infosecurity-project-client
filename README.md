# App Sec Project

This repository is for our App Security Project.

## SQLite3 Installation

1. Visit [this page](https://www.sqlite.org/download.html) and download `sqlite-tools-win32-x86-3320200.zip` (or use this [direct link](https://www.sqlite.org/2020/sqlite-tools-win32-x86-3320200.zip)).
2. In the zip file, extract the 3 EXE files to the `C:\sqlite3` directory.
3. Use the keyboard shortcut `Windows key + R`, type in `systempropertiesadvanced` and press `Enter`. A new window titled "System Properties" should open.
4. Click on the button labeled `Environment Variables` near the bottom.
5. In the `System Variables` section, scroll down and double-click on the row with the `Variable` column equal to `PATH`.
6. Click on `New`, type in `C:\sqlite3`, and press `Enter`.
7. Press `OK` on all the previous dialogs to close them.

## How to set up a virtual environment (venv)

1. Open an administrator command prompt.
2. Change directory to the project folder (e.g. `C:\Users\{username}\App-Sec-Project`).
3. Type in `python -m venv ".\venv"`, press `Enter` and wait for it to finish.
4. Type in `venv\scripts\activate` and press `Enter`.
5. Type in `pip install -r requirements.txt` and press `Enter`.

> **NOTE:** If you installed a new package, please notify other team members, since the `venv` directory will NOT be pushed to the remote repository. In addition, after you have installed the package, update `requirements.txt` by following the steps below:
>
> 1. Open an administrator command prompt.
> 2. Change directory to the project folder (e.g. `C:\Users\{username}\App-Sec-Project`).
> 3. Type in `venv\scripts\activate` and press `Enter`.
> 4. Type in `pip freeze > requirements.txt` and press `Enter`.
> 5. Push the changes.

## How to run the application

1. Open a command prompt window and change directory to the project folder (e.g. `C:\Users\{username}\App-Sec-Project`).
2. If you are using a virtual environment, activate it by typing `venv\scripts\activate` and press `Enter`. If not, then make sure that all packages listed in `requirements.txt` are installed globally, and move on to the next step.
3. Type in `.\run.bat` and press `Enter`.
4. The batch file will generate and display a report on any packages with known security vulnerabilities, and pause execution.
5. Press any key to continue with the execution of the batch file, where it will then proceed to run the web application, and automatically open it in a new browser tab.

## Code Style

This project is formatted using [Black](https://github.com/psf/black). Instructions for how to install black can be found [here](https://github.com/psf/black#installation-and-usage).

Please remember to run `black --line-length=80 .` **before** committing your changes to any Python file(s) to ensure consistent formatting across all Python files in this project.
