# generate_final_report.py
import sys
from pathlib import Path
from PyPDF2 import PdfMerger

from api.shodan_capture import capture_shodan_page
from api.analysis_report import generate_analysis_pdf

def generate_final_report(ip: str, output="reports/final_report.pdf"):
    Path("reports").mkdir(exist_ok=True)

    shodan_pdf = capture_shodan_page(ip, "reports/shodan_page.pdf")
    analysis_pdf = generate_analysis_pdf(ip, "reports/analysis_report.pdf")

    merger = PdfMerger()
    merger.append(shodan_pdf)
    merger.append(analysis_pdf)

    merger.write(output)
    merger.close()

    print("\n===============================")
    print(f"[✔] Final merged report created:")
    print(f"     {output}")
    print("===============================")

    return output


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_final_report.py <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    generate_final_report(target_ip)
