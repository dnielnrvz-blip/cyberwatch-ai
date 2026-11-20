import re
import pandas as pd

def analyze_events(df, db):
    known=[]
    for category, entries in db.items():
        for item in entries:
            if isinstance(item,dict): value=item.get("value",""); desc=item.get("description","")
            else: value=item; desc=""
            if value: known.append((str(value).lower(),category,desc))
    found=[]; anomalies=[]
    for idx,row in df.iterrows():
        row_text=" | ".join(str(v) for v in row.values if pd.notna(v)).lower()
        host=str(row.get("hostname",row.get("host","No especificado")))
        for col,value in row.items():
            if pd.isna(value): continue
            cell=str(value).lower()
            for indicator,category,desc in known:
                pattern=r"(?<![a-z0-9.-])"+re.escape(indicator)+r"(?![a-z0-9.-])"
                if re.search(pattern,cell,re.I):
                    found.append({"row_number":int(idx)+1,"field":str(col),"indicator":indicator,"category":category,"severity":"Alta","description":desc,"evidence":str(value)[:250]})
        for key in ("failed_logins","failed_attempts","failed_login_count"):
            if key in row.index:
                try: n=int(row[key])
                except (ValueError,TypeError): n=0
                if n>=5: anomalies.append({"row_number":int(idx)+1,"hostname":host,"rule":"Múltiples fallos de autenticación","severity":"Media","reason":f"Se registraron {n} intentos fallidos."})
                break
        if any(x in row_text for x in ("powershell_encoded","credential_dump","mimikatz","lsass_dump")):
            anomalies.append({"row_number":int(idx)+1,"hostname":host,"rule":"Palabra clave de actividad de riesgo","severity":"Alta","reason":"El registro contiene una palabra clave que requiere investigación."})
        for key in ("outbound_connections","outbound_count","connection_count"):
            if key in row.index:
                try: n=int(row[key])
                except (ValueError,TypeError): n=0
                if n>=100: anomalies.append({"row_number":int(idx)+1,"hostname":host,"rule":"Volumen elevado de conexiones salientes","severity":"Media","reason":f"El evento informa {n} conexiones salientes."})
                break
    return {"iocs":pd.DataFrame(found,columns=["row_number","field","indicator","category","severity","description","evidence"]).drop_duplicates(),
            "anomalies":pd.DataFrame(anomalies,columns=["row_number","hostname","rule","severity","reason"]).drop_duplicates()}
