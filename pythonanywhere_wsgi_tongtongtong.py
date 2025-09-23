#!/usr/bin/python3.10

"""
WSGI configuration file for PythonAnywhere deployment.
Username: tongtongtong
Project path: /home/tongtongtong/mysite (project directory)

This file should be uploaded to: /var/www/tongtongtong_pythonanywhere_com_wsgi.py
Or configured in Web tab WSGI configuration file.
"""

import sys
import os

# Add your project directory to sys.path
# Project is in /home/tongtongtong/mysite
project_home = '/home/tongtongtong/mysite'
if project_home not in sys.path:
    sys.path = [project_home] + sys.path

# Set the working directory to your project directory
os.chdir(project_home)

# Import your Flask application
from flask_app import app as application

# Debug information (remove in production)
if __name__ == "__main__":
    print("WSGI file loaded successfully")
    print(f"Project home: {project_home}")
    print(f"Python path: {sys.path}")
    print(f"Current working directory: {os.getcwd()}")
    print("Flask app imported successfully!")