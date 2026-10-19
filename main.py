import os
import sys
import json
import requests
from datetime import datetime
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Evita caracteres corruptos (tildes, ñ) en la consola de Windows.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

# En True: 0 créditos consumidos (ideal para pruebas). Cambia a False para análisis real con Gemini.
MOCK_MODE =False

# Modelo configurable desde .env sin tocar el código.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

STRATEGIC_KEYWORDS = [
    "vpn", "firewall", "router", "gateway", "scada", "ics",
    "telecommunications", "exchange", "active directory", "kernel",
    "cisco", "fortinet", "palo alto", "ivanti", "citrix", "microsoft"
]


class ExecutiveCTIBrief(BaseModel):
    cve_id: str = Field(description="Identificador CVE de la vulnerabilidad")
    vector_tecnico_secplus: str = Field(
        description="Explicación concisa del vector técnico usando terminología CompTIA Security+ (RCE, Zero-Day, Auth Bypass, etc.)."
    )
    mitre_attack_mapping: str = Field(
        description="Táctica y técnica de MITRE ATT&CK (ej. T1190 - Exploit Public-Facing Application)."
    )
    lectura_geopolitica_defensa: str = Field(
        description="Análisis de cómo grupos APT estatales pueden explotar el fallo contra defensa, logística o infraestructuras críticas."
    )
    impacto_grc_normativo: str = Field(
        description="Implicaciones en marcos de gobernanza (Directiva NIS2, Esquema Nacional de Seguridad - ENS o NIST CSF)."
    )
    recomendaciones_liderazgo: list[str] = Field(
        description="3 acciones ejecutivas y de mitigación concretas para CISO y Dirección."
    )


def fetch_latest_strategic_vuln() -> dict:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print("[*] Descargando catálogo oficial CISA KEV...")
    response = requests.get(url, timeout=15)
    response.raise_for_status()
    data = response.json()

    vulnerabilities = sorted(
        data.get("vulnerabilities", []),
        key=lambda x: x.get("dateAdded", ""),
        reverse=True
    )

    for vuln in vulnerabilities[:30]:
        texto = (
            f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} "
            f"{vuln.get('shortDescription', '')}"
        ).lower()
        if any(kw in texto for kw in STRATEGIC_KEYWORDS):
            return {
                "cveID": vuln.get("cveID"),
                "vendorProject": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "vulnerabilityName": vuln.get("vulnerabilityName"),
                "dateAdded": vuln.get("dateAdded"),
                "shortDescription": vuln.get("shortDescription"),
                "requiredAction": vuln.get("requiredAction"),
                "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse")
            }

    return vulnerabilities[0]


def analyze_with_gemini(vuln_data: dict) -> ExecutiveCTIBrief:
    if MOCK_MODE:
        print("[!] MODO SIMULACIÓN ACTIVO (0 créditos consumidos)...")
        return ExecutiveCTIBrief(
            cve_id=vuln_data["cveID"],
            vector_tecnico_secplus=(
                "Ejecución Remota de Código (RCE) en servicios perimetrales "
                "expuestos sin requerir autenticación previa."
            ),
            mitre_attack_mapping=(
                "T1190 (Exploit Public-Facing Application) / T1133 (External "
                "Remote Services)"
            ),
            lectura_geopolitica_defensa=(
                "Los activos perimetrales son objetivos prioritarios de "
                "grupos APT estatales para pre-posicionamiento estratégico en redes gubernamentales, contratistas "
                "de defensa y operadores críticos."
            ),
            impacto_grc_normativo=(
                "Exige notificación temprana (<24h) bajo Directiva NIS2 y "
                "revisión de medidas de protección en el Esquema Nacional de Seguridad (ENS - Categoría ALTA)."
            ),
            recomendaciones_liderazgo=[
                "Aplicar parche de seguridad del fabricante o aislar interfaces de administración "
                "expuestas a WAN.",
                "Realizar Threat Hunting sobre registros de acceso perimetral y despliegues VPN de "
                "los últimos 30 días.",
                "Reforzar la segmentación de red aplicando controles Zero Trust (NIST SP "
                "800-207)."
            ]
        )

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or api_key.startswith("PEGA_AQUI"):
        sys.exit(
            "[ERROR] No se encontró GEMINI_API_KEY. Copia .env.example como .env "
            "y añade tu clave de Google AI Studio, o activa MOCK_MODE = True."
        )

    print(f"[*] Ejecutando análisis táctico-estratégico con {GEMINI_MODEL}...")
    client = genai.Client(api_key=api_key)
    prompt = (
        "Actúa como Analista Senior de Ciberinteligencia (CTI) y Defensa. "
        "Analiza esta vulnerabilidad crítica del catálogo CISA KEV y genera un informe ejecutivo. "
        "Redacta en español con ortografía correcta, incluyendo tildes y eñes:\n"
        f"{json.dumps(vuln_data, ensure_ascii=False)}"
    )
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=ExecutiveCTIBrief,
            temperature=0.2,
        ),
    )
    return ExecutiveCTIBrief.model_validate_json(response.text)


def export_briefing(vuln_data: dict, analysis: ExecutiveCTIBrief) -> str:
    fecha = datetime.now().strftime("%Y-%m-%d")
    filename = f"Boletin_CTI_{analysis.cve_id}.md"
    lines = [
        "# BOLETÍN EJECUTIVO DE CIBERINTELIGENCIA Y DEFENSA",
        f"**Fecha:** {fecha} | **Alerta:** `{analysis.cve_id}` | **Activo:** "
        f"{vuln_data['vendorProject']} {vuln_data['product']}",
        f"**Campañas de Ransomware conocidas:** {vuln_data['knownRansomwareCampaignUse']}",
        "",
        "---",
        "",
        "### 1. Análisis Técnico (CompTIA Security+)",
        f"* **Vulnerabilidad:** {vuln_data['vulnerabilityName']}",
        f"* **Vector de Ataque:** {analysis.vector_tecnico_secplus}",
        f"* **Mapeo Táctico (MITRE ATT&CK):** `{analysis.mitre_attack_mapping}`",
        "",
        "### 2. Lectura Geopolítica e Impacto en Defensa",
        analysis.lectura_geopolitica_defensa,
        "",
        "### 3. Gobernanza, Riesgo y Cumplimiento (GRC)",
        f"* **Marco Normativo (NIS2 / ENS / NIST):** {analysis.impacto_grc_normativo}",
        "",
        "### 4. Cursos de Acción Recomendados (Liderazgo / CISO)"
    ]
    for idx, rec in enumerate(analysis.recomendaciones_liderazgo, 1):
        lines.append(f"{idx}. {rec}")
    lines.append("")
    lines.append("---")
    lines.append(
        "*Generado mediante pipeline determinista-agéntico (Python + CISA KEV API + "
        "Google Gemini).*"
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filename


if __name__ == "__main__":
    vuln = fetch_latest_strategic_vuln()
    print(
        f"[+] Vulnerabilidad detectada: {vuln['cveID']} ({vuln['vendorProject']} "
        f"{vuln['product']})"
    )
    briefing = analyze_with_gemini(vuln)
    output = export_briefing(vuln, briefing)
    print(f"[OK] Informe generado en: {output}")