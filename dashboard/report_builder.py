import io
from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
 
 
def build_weekly_report_docx(df_anomalies, week_start: str, week_end: str,
                              total_alerts_week: int, n_clusters: int) -> bytes:
    doc = Document()
 
    title = doc.add_heading("Həftəlik Təhlükəsizlik Hesabatı", level=1)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
 
    meta = doc.add_paragraph()
    meta.add_run(f"Hesabat dövrü: {week_start} — {week_end}\n").bold = False
    meta.add_run(f"Bu həftə ümumi alert sayı: {total_alerts_week}\n")
    meta.add_run(f"Aşkarlanan cluster sayı: {n_clusters}\n")
    meta.add_run(f"Diqqət tələb edən (anomaliya) alert sayı: {len(df_anomalies)}")
 
    doc.add_heading("Diqqət Tələb Edən Alertlər", level=2)
    doc.add_paragraph(
        "Aşağıdakı alertlər ya HDBSCAN modeli tərəfindən bənzərsiz/qeyri-adi "
        "(başqa heç bir grupa uyğun gəlməyən) kimi qiymətləndirilib, ya da "
        "yüksək severity səviyyəsinə malikdir."
    )
 
    headers = ["Alert ID", "Tarix", "Severity", "Alert adı", "Kateqoriya", "Host", "User", "Səbəb", "Təsvir"]
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Light Grid Accent 1"
    hdr_cells = table.rows[0].cells
    for i, h in enumerate(headers):
        hdr_cells[i].text = h
        for p in hdr_cells[i].paragraphs:
            for r in p.runs:
                r.bold = True
 
    for _, row in df_anomalies.iterrows():
        cells = table.add_row().cells
        cells[0].text = str(row.get("alert_id", "-"))
        cells[1].text = str(row.get("creation_dt", "-"))
        cells[2].text = str(row.get("severity", "-"))
        cells[3].text = str(row.get("alert_name", "-"))
        cells[4].text = str(row.get("category", "-"))
        cells[5].text = str(row.get("host_name") or "-")
        cells[6].text = str(row.get("username") or "-")
        cells[7].text = str(row.get("anomaly_reason", "-"))
        desc = str(row.get("description") or "-")
        cells[8].text = desc[:300] + ("..." if len(desc) > 300 else "")
 
    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.add_run("Bu hesabat Cortex XDR + HDBSCAN ML pipeline tərəfindən avtomatik yaradılmışdır.").italic = True
 
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.getvalue()