# ThreatWatch

**Panel de inteligencia de amenazas con datos reales.** Une en una sola web lo que antes eran seis apps sueltas (CVE Monitor, NVD Monitor, SSL Monitor, Feodo Tracker Monitor, URLhaus Monitor y ThreatWatch).

👉 **Abrir:** https://unfantasmaenelsistema.github.io/ThreatWatch/

| Pestaña | Qué muestra | Fuente |
| :-- | :-- | :-- |
| Panel | Resumen: cifras clave, CVE por día, últimas entradas de cada fuente | todas |
| CVE | CVE de los últimos 7 días con filtros, totales de 30 días, búsqueda en todo NVD y probabilidad de explotación (EPSS) | NIST NVD, FIRST EPSS |
| Explotadas (KEV) | Catálogo completo de vulnerabilidades explotadas, con las usadas por ransomware | CISA KEV |
| Certificados SSL | Certificados y subdominios de un dominio según Certificate Transparency | crt.sh |
| URLhaus | URLs que distribuyen malware en los últimos 30 días (desactivadas: `hxxp`, `[.]`) | URLhaus (abuse.ch) |
| Botnets C2 | Servidores de mando y control de Emotet, QakBot, Dridex… | Feodo Tracker (abuse.ch) |
| Ransomware | Últimas víctimas publicadas por los grupos, por grupo, sector y país | ransomware.live |
| Noticias | Titulares de medios y CERT, en español e inglés | RSS |

Español/inglés, tema claro/oscuro y adaptada a móvil.

## Sin datos inventados

Las versiones anteriores tiraban de proxies CORS gratuitos (corsproxy.io, allorigins) que han dejado de funcionar, y cuando fallaban rellenaban la pantalla con datos de ejemplo presentados como reales. Ahora:

- Lo que el navegador **sí** puede pedir directamente se consulta en directo: NVD (búsqueda), EPSS y crt.sh.
- Lo que **no** (CISA KEV, URLhaus, Feodo, ransomware.live y los RSS no envían cabeceras CORS) lo descarga cada hora la Action [`feeds.yml`](.github/workflows/feeds.yml) con [`scripts/fetch_feeds.py`](scripts/fetch_feeds.py) y lo publica como JSON en la rama [`data`](https://github.com/unfantasmaenelsistema/ThreatWatch/tree/data). La web lo lee desde `raw.githubusercontent.com`.
- Si una fuente falla, se conserva su último dato bueno, la barra de estado lo marca en rojo y nunca se inventa nada. Si la Action deja de ejecutarse, la web avisa de que los datos están viejos.

La rama `data` se reescribe en cada ejecución (un solo commit) para que el repositorio no crezca.

## Probar en local

```bash
python scripts/fetch_feeds.py data
python -m http.server 8000
```

Abre http://localhost:8000: en local la web lee `./data/` en lugar de la rama `data`. Solo usa la biblioteca estándar de Python. La descarga de NVD tarda unos 3 minutos porque, sin clave, NVD permite 5 peticiones cada 30 segundos.

## Uso responsable

Datos públicos para formación e información. Las URLs de malware se muestran desactivadas; no las abras fuera de un entorno aislado. Que una empresa aparezca en la pestaña de ransomware refleja lo que afirma el grupo criminal, no un hecho confirmado.

---

**EN —** Threat-intel dashboard with real data only: NVD CVEs + EPSS, CISA KEV, crt.sh certificates, URLhaus, Feodo Tracker, ransomware.live and security news. CORS-blocked feeds are fetched hourly by a GitHub Action into the `data` branch.

Licencia: [MIT](LICENSE) · Hecho por [Un Fantasma en el Sistema](https://www.unfantasmaenelsistema.com) · [GhoStore](https://ghostore.unfantasmaenelsistema.com/)
