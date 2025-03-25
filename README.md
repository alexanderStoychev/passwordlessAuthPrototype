For macOS, run these commands one by one in Terminal:

cd ~/Desktop/passwordless-prototype
python3 -m venv venv
source venv/bin/activate
pip install Flask fido2
python app.py

To exit the virtual environment, type:
deactivate

For Windows, open Command Prompt (or PowerShell) and run these commands:

cd C:\Path\To\passwordless-prototype
python -m venv venv
venv\Scripts\activate
pip install Flask fido2
python app.py

To exit the virtual environment on Windows, type:
deactivate
