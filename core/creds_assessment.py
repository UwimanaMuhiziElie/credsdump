
import zxcvbn 
from authguard.core.utils import load_custom_criteria

def assess_password_strength(password, custom_criteria=None):
    """
    Assess the strength of a password.

    Parameters:
    - password (str): The password to be assessed.
    - custom_criteria (dict): Custom criteria for password assessment (optional).

    Returns:
    - strength (int): The password strength score.
    - suggestions (list): Suggestions for improving the password.
    - educational_insights (list): Educational insights for password improvement.
    """
    if custom_criteria is None:
        custom_criteria = load_custom_criteria()

    result = zxcvbn.zxcvbn(password, custom_criteria=custom_criteria)
    strength = result['score']
    suggestions = result['feedback']['suggestions']

    educational_insights = generate_educational_insights(password, strength, suggestions)

    return strength, suggestions, educational_insights

def generate_educational_insights(password, strength, suggestions):
    """
    Generate educational insights based on the password assessment.

    Parameters:
    - password (str): The password that was assessed.
    - strength (int): The password strength score.
    - suggestions (list): Suggestions for improving the password.

    Returns:
    - educational_insights (list): Educational insights for password improvement.
    """
    insights = []

    if strength == 0:
        insights.append("This password is extremely weak. Consider choosing a stronger one.")
    elif strength == 1:
        insights.append("This password is very weak. Strengthen it by adding more characters and complexity.")
    elif strength == 2:
        insights.append("This password is weak. Enhance its strength by using a mix of characters and avoiding common patterns.")
    elif strength == 3:
        insights.append("This password is moderately strong. Consider adding more complexity for better security.")
    elif strength == 4:
        insights.append("This password is strong. Keep up the good work!")

    insights.extend(suggestions)

    return insights

def assess_credentials(credentials, custom_criteria=None, max_workers=None):
    """
    Assess the strength of passwords in a list of credentials.

    Parameters:
    - credentials (list): List of credentials (each credential is a dictionary with 'username' and 'password').
    - custom_criteria (dict): Custom criteria for password assessment (optional).
    - max_workers (int): Maximum number of parallel workers for assessment (optional).

    Returns:
    - assessment_results (list): List of assessment results for each credential.
      Each result includes 'username', 'password_strength', and 'password_suggestions'.
    """
    assessment_results = []

    if custom_criteria is None:
        custom_criteria = load_custom_criteria()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_credential = {executor.submit(assess_credential, cred, custom_criteria): cred for cred in credentials}

        for future in concurrent.futures.as_completed(future_to_credential):
            credential = future_to_credential[future]
            try:
                result = future.result()
                assessment_results.append(result)
            except Exception as e:
                print(f"Error assessing credential {credential}: {e}")

    return assessment_results

def assess_credential(credential, custom_criteria):
    """
    Assess the strength of a single credential.

    Parameters:
    - credential (dict): A dictionary with 'username' and 'password'.
    - custom_criteria (dict): Custom criteria for password assessment.

    Returns:
    - assessment_result (dict): Result for the assessment.
    """
    username = credential['username']
    password = credential['password']


    strength, suggestions, educational_insights = assess_password_strength(password, custom_criteria=custom_criteria)

    assessment_result = {
        'username': username,
        'password_strength': strength,
        'password_suggestions': suggestions,
        'educational_insights': educational_insights,
    }

    return assessment_result


