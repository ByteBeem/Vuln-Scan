Title: JuVi Scanner

Description:
The Juvi Scanner is a web application built using Python and Flask that helps users identify potential vulnerabilities in web forms. It utilizes web scraping techniques to extract form details from a given URL and submits payloads to identify vulnerabilities.

Features:

Form Detection: The application automatically detects and extracts all HTML forms present on a given URL.
Form Submission: It submits payloads to each form field to check for potential vulnerabilities.
Result Display: The application displays detected vulnerabilities, including details of the vulnerable forms.
User Interface: Users can interact with the application through a simple web interface, entering the URL they wish to scan.
Dynamic Scanning: Users can perform scans on various websites to identify potential vulnerabilities.
Usage:

Enter the URL of the website you want to scan for vulnerabilities.
Click the "Scan" button to initiate the scanning process.
Once the scan is complete, the application will display any detected vulnerabilities.
Technologies Used:

Python
Flask
Requests (for HTTP requests)
BeautifulSoup (for web scraping)
Purpose:
The JuVi Scanner is designed to help developers and security professionals identify and mitigate vulnerabilities in web applications. By automating the scanning process, it simplifies the task of identifying potential security risks and helps improve the overall security posture of web applications.

Note: This application is intended for educational and informational purposes only. It should not be used for malicious intent or unauthorized scanning of websites without proper consent.
