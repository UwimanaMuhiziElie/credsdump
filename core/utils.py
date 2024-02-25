
import json
import csv
import os

def load_credentials_from_file(file_path, file_format='json'):
    """
    Load credentials from a file.
    Parameters:
    - file_path (str): Path to the file containing credentials.
    - file_format (str): Format of the file ('json' or 'csv'). Default is 'json'.
    Returns:
    - credentials (list): List of credentials (each credential is a dictionary with 'username' and 'password').
    """
    try:
        with open(file_path, 'r') as file:
            if file_format == 'json':
                credentials = json.load(file)
            elif file_format == 'csv':
                credentials = list(csv.DictReader(file))
            else:
                print(f"Unsupported file format: {file_format}. Defaulting to JSON.")
                credentials = json.load(file)

        return credentials
    except Exception as e:
        print(f"Error loading credentials from file {file_path}: {e}")
        return []

def save_credentials_to_file(credentials, file_path, file_format='json'):
    """
    Save credentials to a file.
    Parameters:
    - credentials (list): List of credentials (each credential is a dictionary with 'username' and 'password').
    - file_path (str): Path to the file where credentials will be saved.
    - file_format (str): Format of the file ('json' or 'csv'). Default is 'json'.
    """
    try:
        with open(file_path, 'w', newline='') as file:
            if file_format == 'json':
                json.dump(credentials, file, indent=2)
            elif file_format == 'csv':
                fieldnames = ['username', 'password']
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(credentials)
            else:
                print(f"Unsupported file format: {file_format}. Defaulting to JSON.")
                json.dump(credentials, file, indent=2)

        print(f"Credentials saved to {file_path} in {file_format} format.")
    except Exception as e:
        print(f"Error saving credentials to file {file_path}: {e}")

def load_custom_criteria(custom_criteria_path='data/custom_criteria.json'):
    """
    Load custom password strength criteria from a file.
    Parameters:
    - custom_criteria_path (str): Path to the file containing custom criteria. Default is 'data/custom_criteria.json'.
    Returns:
    - custom_criteria (dict): Custom password strength criteria.
    """
    try:
        with open(custom_criteria_path, 'r') as file:
            custom_criteria = json.load(file)

        return custom_criteria
    except Exception as e:
        print(f"Error loading custom criteria from file {custom_criteria_path}: {e}")
        return {}

def save_custom_criteria(custom_criteria, custom_criteria_path='data/custom_criteria.json'):
    """
    Save custom password strength criteria to a file.
    Parameters:
    - custom_criteria (dict): Custom password strength criteria.
    - custom_criteria_path (str): Path to the file where custom criteria will be saved. Default is 'data/custom_criteria.json'.
    """
    try:
        with open(custom_criteria_path, 'w') as file:
            json.dump(custom_criteria, file, indent=2)
        print(f"Custom criteria saved to {custom_criteria_path}.")
    except Exception as e:
        print(f"Error saving custom criteria to file {custom_criteria_path}: {e}")
