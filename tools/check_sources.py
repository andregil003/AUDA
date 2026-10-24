"""Prueba de integración optativa: consulta publicaciones oficiales para este host."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.host import collect
from src.intelligence import identities,Sources

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    host=collect()
    entries,states=Sources().publications(host,identities(host))
    print(json.dumps({'fuentes':states,'correcciones_relacionadas':len(entries),
                      'muestras':[{'cve':e['cveID'],'parche':e['patch']} for e in entries[:2]]},ensure_ascii=False,indent=2))
