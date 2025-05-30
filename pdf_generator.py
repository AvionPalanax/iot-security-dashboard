from fpdf import FPDF
import io
import re

def sanitize_text(text):
    # Replace emoji or unsupported symbols
    if isinstance(text, str):
        return re.sub(r'[^\x00-\x7F]+', '', text.replace("🔒", "[LOCK]"))
    return str(text)

def generate_pdf(anomalies_df, policy_df, response_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="IoT Security Dashboard Report", ln=True, align='C')
    pdf.ln(10)

    # Anomalies Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Recent Anomalies Detected:", ln=True)
    pdf.set_font("Arial", size=10)
    if anomalies_df.empty:
        pdf.cell(200, 8, txt="No anomalies detected.", ln=True)
    else:
        for _, row in anomalies_df.tail(10).iterrows():
            device_id = sanitize_text(row.get("device_id", "N/A"))
            score = row.get("anomaly_score", "N/A")
            score_text = f"{score:.2f}" if isinstance(score, float) else sanitize_text(score)
            pdf.cell(200, 8, txt=f"{device_id} - Score: {score_text}", ln=True)
    pdf.ln(5)

    # Policy Violations Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Policy Violations:", ln=True)
    pdf.set_font("Arial", size=10)
    if policy_df.empty:
        pdf.cell(200, 8, txt="No policy violations found.", ln=True)
    else:
        for _, row in policy_df.tail(10).iterrows():
            device_id = sanitize_text(row.get("device_id", "N/A"))
            vpn = sanitize_text(row.get("vpn", "N/A"))
            mfa = sanitize_text(row.get("mfa", "N/A"))
            fw = sanitize_text(row.get("firewall", "N/A"))
            pdf.cell(200, 8, txt=f"{device_id} - VPN: {vpn}, MFA: {mfa}, FW: {fw}", ln=True)
    pdf.ln(5)

    # Automated Threat Responses Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Automated Threat Responses:", ln=True)
    pdf.set_font("Arial", size=10)

    filtered_response = response_df[
        response_df['auto_action'].astype(str).str.strip().ne('') &
        response_df['auto_action'].astype(str).str.lower().ne('none')
    ]

    if filtered_response.empty:
        pdf.cell(200, 8, txt="No threat responses available.", ln=True)
    else:
        for _, row in filtered_response.tail(10).iterrows():
            timestamp = sanitize_text(row.get("timestamp", "N/A"))
            device_id = sanitize_text(row.get("device_id", "N/A"))
            auto_action = sanitize_text(row.get("auto_action", "N/A")).strip()
            pdf.cell(200, 8, txt=f"{timestamp} - {device_id} - {auto_action}", ln=True)

    output = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1', errors='ignore')
    output.write(pdf_bytes)
    output.seek(0)
    return output.read()
