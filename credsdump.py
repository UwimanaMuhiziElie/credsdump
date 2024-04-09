
import argparse
from credsdump.core.credential_dump import extract_credentials
from credsdump.core.credential_assessment import assess_credentials
from credsdump.core.recommendations import generate_password_recommendations
from credsdump.core.reporting import generate_report
from credsdump.core.utils import load_credentials_from_file, save_credentials_to_file

def main():
    parser = argparse.ArgumentParser(description="Welcome to credsdump- Your Password Security Assessment Tool")
    parser.add_argument(
        "--action",
        choices=["dump_credentials", "assess_credentials", "generate_recommendations", "generate_report"],
        required=True,
        help="Specify the action you want to perform: dump_credentials, assess_credentials, generate_recommendations, generate_report",
    )

    parser.add_argument(
        "--target-environment",
        help="Specify the target environment for credential extraction (e.g:ActiveDirectory, CustomApp)",
    )

    parser.add_argument(
        "--custom-parameter",
        help="Specify a custom parameter for the chosen action (e.g:file path, username, etc.)",
    )

    parser.add_argument(
        "--input-file",
        help="Specify the input file path for actions that require it (e.g: assess_credentials)",
    )

    parser.add_argument(
        "--output-file",
        help="Specify the output file path for actions that require it (e.g:generate_report)",
    )

    args = parser.parse_args()

    if args.action == "dump_credentials":
        credentials = extract_credentials(args.target_environment, args.custom_parameter)
        print("Dumped Credentials:")
        print(credentials)

    elif args.action == "assess_credentials":
        if args.input_file:
            credentials = load_credentials_from_file(args.input_file)
            assessment_results = assess_credentials(credentials)
            print("Assessment Results:")
            print(assessment_results)
        else:
            print("Error: --input-file is required for assess_credentials action.")

    elif args.action == "generate_recommendations":
        if args.input_file:
            credentials = load_credentials_from_file(args.input_file)
            assessment_results = assess_credentials(credentials)
            recommendations = generate_password_recommendations(assessment_results)
            print("Password Recommendations:")
            print(recommendations)
        else:
            print("Error: --input-file is required for generate_recommendations action.")

    elif args.action == "generate_report":
        if args.input_file and args.output_file:
            credentials = load_credentials_from_file(args.input_file)
            assessment_results = assess_credentials(credentials)
            recommendations = generate_password_recommendations(assessment_results)
            generate_report(assessment_results, recommendations, args.output_file)
            print(f"Report generated successfully. Check '{args.output_file}'.")
        else:
            print("Error: --input-file and --output-file are required for generate_report action.")

if __name__ == "__main__":
    main()
