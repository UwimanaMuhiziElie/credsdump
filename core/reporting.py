
import os
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from datetime import datetime

def generate_report(assessment_results, recommendations, output_folder=None):
    if output_folder is None:
        output_folder = get_default_output_folder()
    report_path = os.path.join(output_folder, 'authguard_report.pdf')
    generate_pdf_report(report_path, assessment_results, recommendations)

    print(f"Report generated successfully. Check '{report_path}'.")

def get_default_output_folder():
    return 'temp' if os.name == 'posix' else 'downloads'

def generate_pdf_report(report_path, assessment_results, recommendations):
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()

    report_content = []

 
    title = Paragraph("<b>AuthGuard Security Assessment Report</b>", styles['Title'])
    report_content.append(title)

    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = Paragraph(f"<i>Date: {current_date}</i>", styles['Normal'])
    report_content.append(date_str)
    report_content.append(Spacer(1, 12))
    assessment_section = [
        Paragraph("<b>Assessment Results</b>", styles['Heading1']),
        Spacer(1, 12),
    ]

    assessment_table_data = [('Username', 'Password Strength', 'Password Suggestions')]
    for result in assessment_results:
        username = result['username']
        password_strength = result['password_strength']
        password_suggestions = ', '.join(result['password_suggestions'])
        assessment_table_data.append((username, str(password_strength), password_suggestions))

    assessment_table = Table(assessment_table_data, hAlign='CENTER')
    assessment_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), '#4285F4'),
                                          ('TEXTCOLOR', (0, 0), (-1, 0), 'white'),
                                          ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                          ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                          ('BACKGROUND', (0, 1), (-1, -1), '#eeeeee'),
                                          ('GRID', (0, 0), (-1, -1), 1, '#888888')]))

    assessment_section.append(assessment_table)
    report_content.extend(assessment_section)
    report_content.append(Spacer(1, 12))

    recommendations_section = [
        Paragraph("<b>Recommendations</b>", styles['Heading1']),
    ]
    for recommendation in recommendations:
        recommendations_section.append(Paragraph(recommendation, styles['Normal']))
    report_content.extend(recommendations_section)
    report_content.append(Spacer(1, 12))

    statistics_section = [
        Paragraph("<b>Statistics</b>", styles['Heading1']),
        Spacer(1, 12),
        Paragraph(f"Total Assessments: {len(assessment_results)}", styles['Normal']),
    ]
    report_content.extend(statistics_section)

    doc.build(report_content)

