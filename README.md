# CyberWatch AI — Web Prototype

## Ejecutar localmente en Windows
1. Instala Python 3.11 o 3.12 desde https://www.python.org/downloads/windows/ y marca Add python.exe to PATH.
2. Abre CMD en esta carpeta.
3. Ejecuta:
   py -m venv .venv
   .venv\\Scripts\\activate
   pip install -r requirements.txt
   streamlit run app.py
4. Abre http://localhost:8501

## Publicar en Internet con Streamlit Community Cloud
1. Crea una cuenta en https://github.com/ y un repositorio nuevo llamado cyberwatch-ai.
2. Sube todos los archivos y carpetas del ZIP al repositorio. No subas .venv ni datos confidenciales.
3. Entra en https://share.streamlit.io/ y conecta GitHub.
4. Selecciona el repositorio, la rama main y el archivo app.py.
5. Pulsa Deploy. Streamlit instalará las dependencias desde requirements.txt.
6. La aplicación quedará disponible en una URL de Streamlit.

IMPORTANTE: trata la URL como pública. No subas registros confidenciales, credenciales, datos personales ni indicadores propietarios. Configura controles de acceso apropiados antes de cualquier uso empresarial.

## Alcance
Carga CSV/JSON, coincidencia local IoC, reglas heurísticas de anomalías y exportación de alertas.
No incluye todavía SIEM/EDR, reputación externa, modelo ML entrenado, autenticación ni bloqueo automático.
Una coincidencia es una pista para investigar, no prueba de compromiso.
