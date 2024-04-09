from authguard.core.utils import load_custom_criteria

def generate_password_recommendations(assessment_results):
    """
    Generate password-related recommendations based on the assessment results.

    Parameters:
    - assessment_results (list): List of assessment results for each credential.
      Each result includes 'username', 'password_strength', 'password_suggestions', and 'educational_insights'.

    Returns:
    - recommendations (list): List of recommendations.
    """
    recommendations = []
    custom_criteria = load_custom_criteria()

    for result in assessment_results:
        username = result['username']
        password_strength = result['password_strength']
        password_suggestions = result['password_suggestions']
        educational_insights = result['educational_insights']

        if password_strength < custom_criteria.get('minimum_strength', 3):
            recommendations.append(f"User '{username}' has a weak password. Consider enforcing stronger password policies.")

        recommendations.extend(generate_custom_recommendations(username, password_strength, password_suggestions))

        recommendations.extend(educational_insights)

    recommendations.extend(generate_actionable_recommendations(assessment_results))

    return recommendations

def generate_custom_recommendations(username, password_strength, password_suggestions):
    """
    Generate custom recommendations based on specific criteria.

    Parameters:
    - username (str): User's username.
    - password_strength (int): Password strength score.
    - password_suggestions (list): Suggestions for improving the password.

    Returns:
    - custom_recommendations (list): List of custom recommendations.
    """
    custom_recommendations = []

    if 'compromised' in password_suggestions:
        custom_recommendations.append(f"User '{username}' has a password compromised in data breaches. "
                                      "Consider changing it immediately.")

    if 'reused' in password_suggestions:
        custom_recommendations.append(f"User '{username}' has reused a password. "
                                      "Consider using a unique password for each account.")

    if password_strength == 0:
        custom_recommendations.append(f"User '{username}' has an extremely weak password. "
                                      "Enforce a minimum password length and complexity.")


    return custom_recommendations

def generate_actionable_recommendations(assessment_results):
    """
    Generate actionable recommendations based on the overall assessment results.

    Parameters:
    - assessment_results (list): List of assessment results for each credential.
      Each result includes 'username', 'password_strength', 'password_suggestions', and 'educational_insights'.

    Returns:
    - actionable_recommendations (list): List of actionable recommendations.
    """
    actionable_recommendations = []

    for result in assessment_results:
        username = result['username']
        password_strength = result['password_strength']

        if password_strength < 3:
            actionable_recommendations.append(f"User '{username}' has a weak password. "
                                              "Consider enforcing stronger password policies.")

    actionable_recommendations.append("Consider implementing multi-factor authentication (MFA) for extra security security layer.")

    for result in assessment_results:
        username = result['username']
        password_suggestions = result['password_suggestions']

        if 'compromised' in password_suggestions:
            actionable_recommendations.append(f"User '{username}' has a password compromised in data breaches. "
                                              "Alert and consider changing it immediately.")

    return actionable_recommendations
