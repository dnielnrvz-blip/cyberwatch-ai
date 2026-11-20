import json
from pathlib import Path
import pandas as pd
import streamlit as st
from detection.engine import analyze_events

ROOT = Path(__file__).parent
st.set_page_config(page_title="CyberWatch AI", page_icon="◈", layout="wide")
st.markdown("""
<style>
.stApp{background:#f7f8fa;color:#17212b}
.block-container{max-width:1400px;padding-top:2rem}
[data-testid="stSidebar"]{background:#fff;border-right:1px solid #e7ebef}
[data-testid="stMetric"]{background:#fff;border:1px solid #e7ebef;padding:16px;border-radius:12px}
h1,h2,h3{letter-spacing:-.03em;color:#17212b}
.small{color:#667085;font-size:.9rem}
</style>
""", unsafe_allow_html=True)

def demo(): return pd.read_csv(ROOT/"data"/"sample_events.csv")
def read_upload(f):
    if f.name.lower().endswith(".csv"): return pd.read_csv(f)
    obj=json.load(f)
    if isinstance(obj,dict): obj=obj.get("events",[obj])
    if not isinstance(obj,list): raise ValueError("El JSON debe ser una lista o incluir 'events'.")
    return pd.json_normalize(obj)

if "events" not in st.session_state: st.session_state.events=demo()
if "results" not in st.session_state: st.session_state.results=None

with st.sidebar:
    st.markdown("## ◈ CyberWatch AI")
    st.caption("SECURITY INTELLIGENCE")
    page=st.radio("NAVEGACIÓN",["Resumen","Detector IoC","Anomalías","Centro de alertas","Acerca del proyecto"])
    st.divider()
    st.caption("Prototipo · Datos de laboratorio")
    st.caption("Sin bloqueos ni acciones automáticas.")

events=st.session_state.events
results=st.session_state.results
st.title("CyberWatch AI")
st.markdown('<p class="small">Detección y análisis de amenazas · Prototipo web</p>',unsafe_allow_html=True)

if page=="Resumen":
    st.subheader("Resumen ejecutivo")
    iocs=0 if results is None else len(results["iocs"])
    anomalies=0 if results is None else len(results["anomalies"])
    a,b,c,d=st.columns(4)
    a.metric("Eventos cargados",f"{len(events):,}")
    b.metric("Coincidencias IoC",f"{iocs:,}")
    c.metric("Anomalías",f"{anomalies:,}")
    d.metric("Hallazgos",f"{iocs+anomalies:,}")
    st.divider()
    x,y=st.columns([1.5,1])
    with x:
        st.markdown("#### Actividad reciente")
        st.dataframe(events.head(10),use_container_width=True,hide_index=True)
    with y:
        st.markdown("#### Estado del prototipo")
        st.write("**Ingesta:** CSV y JSON")
        st.write("**IoC:** comparación con base local")
        st.write("**Anomalías:** reglas heurísticas")
        st.write("**Respuesta:** deshabilitada")
        st.info("Ejecuta un análisis desde Detector IoC para ver resultados.")
    st.caption("Las métricas se calculan con los datos cargados; no son cifras decorativas.")

elif page=="Detector IoC":
    st.subheader("Detector de Indicadores de Compromiso")
    st.caption("Carga registros autorizados y compara sus campos con indicadores locales.")
    f=st.file_uploader("Seleccionar registros",type=["csv","json"])
    c1,c2=st.columns([1,3])
    with c1:
        if st.button("Usar datos de demostración"):
            st.session_state.events=demo(); st.session_state.results=None; st.rerun()
    if f is not None:
        try:
            st.session_state.events=read_upload(f); st.session_state.results=None
            events=st.session_state.events
            st.success(f"Archivo cargado: {len(events)} registros.")
        except Exception as e: st.error(f"No se pudo leer el archivo: {e}")
    st.markdown("#### Vista previa")
    st.dataframe(events.head(25),use_container_width=True,hide_index=True)
    if st.button("Ejecutar análisis IoC y anomalías",type="primary"):
        with open(ROOT/"data"/"ioc_database.json",encoding="utf-8") as f: db=json.load(f)
        st.session_state.results=analyze_events(events,db); st.rerun()
    if results is not None:
        out=results["iocs"]
        a,b,c=st.columns(3)
        a.metric("Coincidencias",len(out))
        b.metric("Indicadores únicos",out.indicator.nunique() if not out.empty else 0)
        c.metric("Registros afectados",out.row_number.nunique() if not out.empty else 0)
        if out.empty: st.success("No se encontraron coincidencias en la base local.")
        else:
            st.warning("Coincidencias encontradas. Requieren validación humana.")
            st.dataframe(out,use_container_width=True,hide_index=True)
            st.download_button("Descargar hallazgos IoC",out.to_csv(index=False).encode(), "cyberwatch_ioc.csv","text/csv")

elif page=="Anomalías":
    st.subheader("Detección inicial de anomalías")
    st.info("Reglas heurísticas explicables. Todavía no se utiliza un modelo de machine learning entrenado.")
    if results is None: st.warning("Ejecuta primero el análisis desde Detector IoC.")
    else:
        out=results["anomalies"]; st.metric("Eventos señalados",len(out))
        if out.empty: st.success("No se encontraron eventos que coincidan con las reglas actuales.")
        else:
            st.dataframe(out,use_container_width=True,hide_index=True)
            st.download_button("Descargar anomalías",out.to_csv(index=False).encode(),"cyberwatch_anomalies.csv","text/csv")
    st.markdown("**Reglas incluidas**")
    st.write("- Cinco o más intentos fallidos de autenticación.")
    st.write("- Palabras clave de riesgo: `powershell_encoded`, `credential_dump`, `mimikatz` o `lsass_dump`.")
    st.write("- Cien o más conexiones salientes reportadas en un evento.")

elif page=="Centro de alertas":
    st.subheader("Centro de alertas")
    if results is None: st.info("Ejecuta un análisis para generar alertas.")
    else:
        rows=[]
        for _,r in results["iocs"].iterrows():
            rows.append({"tipo":"IoC","severidad":r.severity,"indicador":r.indicator,"evidencia":r.evidence,"registro":r.row_number})
        for _,r in results["anomalies"].iterrows():
            rows.append({"tipo":"Anomalía","severidad":r.severity,"indicador":r.rule,"evidencia":r.reason,"registro":r.row_number})
        alerts=pd.DataFrame(rows)
        if alerts.empty: st.success("No hay alertas.")
        else:
            st.dataframe(alerts,use_container_width=True,hide_index=True)
            st.download_button("Exportar alertas",alerts.to_csv(index=False).encode(),"cyberwatch_alerts.csv","text/csv")

else:
    st.subheader("Acerca del proyecto")
    st.markdown("""
**CyberWatch AI** es un prototipo de apoyo a la defensa cibernética.

**Alcance actual**
- Ingesta manual de CSV y JSON.
- Comparación local de IP, dominios, URLs y hashes.
- Reglas heurísticas iniciales para anomalías.
- Consolidación y exportación de alertas.

**Pendiente para versiones posteriores**
- Integración SIEM/EDR.
- Consultas a fuentes externas de reputación.
- Modelo ML entrenado y análisis contextual con IA.
- Autenticación, auditoría y controles de producción.

**Seguridad:** utiliza solo datos sintéticos, anonimizados o autorizados. No cargues registros confidenciales en una demo pública.
""")

st.divider()
st.caption("CyberWatch AI · Prototipo defensivo · Una coincidencia no confirma por sí sola un compromiso.")
