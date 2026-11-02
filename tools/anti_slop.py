"""
# Tool: anti_slop.py

## Metadata
- Nombre: anti_slop.py
- Versión: 1.0 (Framework Anti-Slop & Humanizador Pericial SOC L2)
- Lenguaje: Python 3.11+
- Creada en proyecto: SOC_Agentico
- Fecha de creación: 01-11-2026
- Descripción: Filtro y auditor de patrones sintéticos de IA (basado en petergyang/no-ai-slop y preferencias globales de Antigravity). Sanea textos eliminando conectores formulaicos, palabras infladas, gerundios terminales, contrastes binarios y guiones largos, asegurando un tono pericial sobrio y humano.
- Dependencias: re
"""

import re
from typing import Tuple, List, Dict, Any

# Patrones de detección de Slop según estándar no-ai-slop
PATRONES_SLOP = [
    (r"\brobust[ao]s?\b|\brobustez\b", "Palabra inflada (robusto/robustez)", "Sustituir por 'alta seguridad', 'resiliente' o término técnico específico."),
    (r"\bfacilit[aóe]n?\b|\bfacilitaron\b|\bfacilitando\b", "Verbo genérico de IA (facilitar)", "Usar verbo directo: 'permitió', 'determinó', 'posibilitó'."),
    (r"\bapalan(?:car|ca|có|que|cando)\b", "Jerga de IA (apalancar)", "Sustituir por 'aprovechar', 'utilizar'."),
    (r"\bempoder(?:ar|a|ó|ando)\b", "Jerga de IA (empoderar)", "Eliminar o sustituir por 'capacitar', 'autorizar'."),
    (r"\bholístic[ao]s?\b", "Adjetivo inflado (holístico)", "Usar 'integral', 'global'."),
    (r"\bintrincad[ao]s?\b", "Adjetivo cliché (intrincado)", "Usar 'complejo', 'detallado'."),
    (r"\bmeticulos[ao]s?\b|\bmeticulosamente\b", "Adjetivo inflado (meticuloso)", "Usar 'detallado', 'metódico'."),
    (r"\bno\s+[\w\s]{2,40},\s+sino\s+[\w\s]{2,40}\b", "Contraste binario ('no X, sino Y')", "Afirmar Y directamente sin negar X previamente."),
    (r",\s+(?:garantizando|asegurando|permitiendo|demostrando|destacando|revelando|subrayando)\s+[\w\s]{5,50}\.", "Gerundio conclusivo superficial", "Dividir en dos oraciones o enlazar con sujeto pericial activo."),
    (r"\bEn\s+primer\s+lugar,\b|\bEn\s+segundo\s+lugar,\b|\bEn\s+tercer\s+lugar,\b", "Simetría robótica en enumeración", "Variar la estructura de los párrafos."),
    (r"\b(?:el\s+detalle|lo\s+crucial|la\s+clave|el\s+resultado|lo\s+sorprendente):\s+[a-z]", "Revelación con dos puntos (Colon reveal)", "Integrar como oración corrida."),
    (r"\b(?:aquí\s+está\s+el\s+detalle|la\s+verdad\s+es\s+que|lo\s+que\s+nadie\s+te\s+dice|lo\s+cierto\s+es\s+que)\b", "Apertura vacía (Throat-clearing)", "Eliminar la frase."),
    (r"\b(?:fundamentalmente|crucialmente|literalmente|inherentemente|inevitablemente)\b", "Adverbio intensificador vacío", "Eliminar el adverbio."),
    (r"\b(?:es\s+importante\s+(?:destacar|se[ñn]alar|mencionar|notar|recordar)\s+que|cabe\s+(?:destacar|mencionar|se[ñn]alar)\s+que|es\s+fundamental\s+(?:tener\s+en\s+cuenta|destacar|se[ñn]alar)\s+que|es\s+crucial\s+(?:mencionar|notar|destacar)\s+que)\b", "Conector formulaico de IA", "Eliminar y comenzar directo con la evidencia."),
    (r"\b(?:en\s+conclusi[oó]n|a\s+modo\s+de\s+resumen|en\s+resumidas\s+cuentas|a\s+manera\s+de\s+cierre),\s*", "Cierre formulaico de IA", "Reemplazar por el dictamen pericial directo."),
    (r"—", "Guión largo tipográfico (em-dash)", "Sustituir por guión estándar '-' o coma según regla de Antigravity.")
]

# Reglas de sustitución directa para el saneador
REGLAS_SANEAMIENTO = [
    # 1. Eliminar aperturas y conectores formulaicos de IA
    (r"(?i)\b(?:es\s+importante\s+(?:destacar|se[ñn]alar|mencionar|notar|recordar)\s+que|cabe\s+(?:destacar|mencionar|se[ñn]alar)\s+que|es\s+fundamental\s+(?:tener\s+en\s+cuenta|destacar|se[ñn]alar|tomar\s+medidas)\s+que|es\s+crucial\s+(?:mencionar|notar|destacar)\s+que)\s*", ""),
    (r"(?i)\b(?:en\s+el\s+vertiginoso\s+mundo\s+de|un\s+tapiz\s+de|navegar\s+el\s+panorama\s+de|un\s+faro\s+de|a\s+continuaci[oó]n\s+se\s+presenta\s+un\s+desglose\s+exhaustivo)\s*", ""),
    (r"(?i)\b(?:en\s+conclusi[oó]n|a\s+modo\s+de\s+resumen|en\s+resumidas\s+cuentas|a\s+manera\s+de\s+cierre),\s*", "Dictamen pericial: "),
    
    # 2. Sustitución de palabras infladas
    (r"(?i)\brobusto\b", "de alta seguridad"),
    (r"(?i)\brobusta\b", "resiliente"),
    (r"(?i)\brobustos\b", "endurecidos"),
    (r"(?i)\brobustas\b", "resilientes"),
    (r"(?i)\brobustez\b", "resiliencia"),
    (r"(?i)\bfacilitando\b", "posibilitando"),
    (r"(?i)\bfacilitar\b", "permitir"),
    (r"(?i)\bfacilit[oó]\b", "determinó"),
    (r"(?i)\bapalan(?:car|ca|có|que)\b", "utilizar"),
    (r"(?i)\bapalancando\b", "aprovechando"),
    (r"(?i)\bempoder(?:ar|a|ó|ando)\b", "capacitar"),
    (r"(?i)\bholístic[ao]s?\b", "integral"),
    (r"(?i)\bintrincad[ao]s?\b", "complejo"),
    (r"(?i)\bmeticulos[ao]s?\b", "detallado"),
    (r"(?i)\bmeticulosamente\b", "metódicamente"),

    # 3. Eliminar adverbios vacíos intensificadores
    (r"(?i)\b(?:crucialmente|fundamentalmente|inherentemente|inevitablemente)\s+", ""),

    # 4. Sustituir guiones largos em-dash
    (r"—", "-"),

    # 5. Eliminar disclaimers automáticos de LLM
    (r"(?i)como\s+modelo\s+de\s+lenguaje[^\.\n]*[\.\n]", ""),
    (r"(?i)tenga\s+en\s+cuenta\s+que\s+este\s+informe[^\.\n]*[\.\n]", "")
]


def audit_slop(text: str) -> List[Dict[str, Any]]:
    """Audita el texto y retorna la lista de patrones de IA encontrados."""
    if not text:
        return []

    hallazgos = []
    lineas = text.splitlines()

    for num_linea, linea in enumerate(lineas, 1):
        if linea.strip().startswith("```") or linea.strip().startswith("C:\\"):
            continue

        for patron, nombre, sugerencia in PATRONES_SLOP:
            for match in re.finditer(patron, linea, re.IGNORECASE):
                hallazgos.append({
                    "linea": num_linea,
                    "patron": nombre,
                    "texto": match.group(0),
                    "contexto": linea.strip()[:100],
                    "sugerencia": sugerencia
                })

    return hallazgos


def sanitize_anti_slop(text: str) -> Tuple[str, int]:
    """
    Sanea exhaustivamente el texto aplicando reglas anti-slop:
    elimina clichés, desautomatiza fórmulas y corrige capitalización.
    Retorna (texto_limpio, num_correcciones).
    """
    if not text:
        return "", 0

    original = text
    correcciones = 0

    for patron, reemplazo in REGLAS_SANEAMIENTO:
        matches = len(re.findall(patron, text))
        if matches > 0:
            text = re.sub(patron, reemplazo, text)
            correcciones += matches

    # Reparar capitalización tras eliminar conectores iniciales de oración
    # (ej. "el incidente..." -> "El incidente...")
    text = re.sub(
        r"(^|[\.\?\!]\s+)([a-z])",
        lambda m: m.group(1) + m.group(2).upper(),
        text
    )

    # Limpiar dobles espacios accidentales
    text = re.sub(r"[ ]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip(), correcciones


def get_anti_slop_prompt_directive() -> str:
    """Retorna la directiva obligatoria para inyectar en los prompts de Ollama."""
    return """
DIRECTIVAS ESTRICTAS DE REDACCIÓN PERICIAL ANTI-SLOP (NO-AI-SLOP):
- Está TOTALMENTE PROHIBIDO usar fórmulas como 'Es importante destacar', 'Cabe mencionar', 'Es crucial', 'En conclusión', 'robusto', 'facilitar', 'un tapiz', 'en el vertiginoso mundo'.
- CERO contrastes binarios ('no X, sino Y'). Afirma los datos directamente.
- CERO gerundios terminales superficiales (', permitiendo...', ', asegurando...').
- CERO guiones largos ('—'). Usa guión estándar '-' o dos puntos.
- Tono: Analista Forense y de CTI Nivel 2. Seco, fáctico, pericial, apoyado estrictamente en registros y Event IDs.
"""

