#!/usr/bin/env python3
# ==============================================================================
# final_adapted_report.py
#
# Descripción:
#   Adapta la lógica y el estilo del script 'generate_advanced_update_report.py'
#   a la arquitectura de ejecución en paralelo para múltiples servidores.
#   Genera un reporte consolidado con el formato solicitado.
# ==============================================================================
import subprocess
import os
import sys
from datetime import datetime
import html
import concurrent.futures

# --- CONFIGURACIÓN ---
SERVERS_TO_AUDIT = [
    "10.18.16.66", "10.18.16.67", "10.18.16.68", "10.18.16.69", "10.18.16.70",
    "10.18.16.71", "10.18.16.2", "10.18.16.3", "10.18.16.4", "10.18.16.84",
    "10.18.16.85", "10.18.16.130", "10.18.16.131", "10.18.16.132", "10.18.16.78",
    "10.18.16.79", "10.18.16.80", "10.18.16.72", "10.18.16.73", "10.18.16.74",
    "10.18.16.75", "10.18.16.76", "10.18.16.77", "10.18.16.5", "10.18.16.6",
    "10.18.16.7", "10.18.16.86", "10.18.16.87", "10.18.16.162", "10.18.16.163",
    "10.18.16.164", "10.18.16.81", "10.18.16.82", "10.18.16.83"
]
SSH_USER = "admin_kalvarez"
REPORT_PATH = "./multi_server_adapted_report.html"
MAX_WORKERS = 20

# --- AGENTE REMOTO ADAPTADO ---
REMOTE_AGENT_SCRIPT = """
set -o pipefail
# Este agente replica la lógica del script original que le gustó.
REBOOT_PACKAGES=("kernel" "glibc" "systemd" "dbus" "linux-firmware")
DELIMITER="|:|:"

# Imprimir información del servidor
echo "SERVER_INFO${DELIMITER}$(uname -n)"

# Obtener actualizaciones
updates_output=$(sudo -n dnf check-update --quiet 2>/dev/null || true)
if [ -z "$updates_output" ]; then exit 0; fi

# Procesar cada actualización
while read -r line; do
    if [[ "$line" == "Last metadata expiration check:"* ]] || [[ -z "$line" ]]; then continue; fi
    
    pkg_full_name=$(echo "$line" | awk '{print $1}')
    new_version=$(echo "$line" | awk '{print $2}')
    repo=$(echo "$line" | awk '{print $3}')
    pkg_name=${pkg_full_name%%.*}
    
    current_version=$(sudo -n rpm -q "$pkg_name" --queryformat '%{VERSION}-%{RELEASE}' 2>/dev/null || echo "No instalado")
    
    # Lógica de acción requerida
    action_text="Ninguno (biblioteca/herramienta)"; action_class="none"
    for p in "${REBOOT_PACKAGES[@]}"; do
        if [[ "$pkg_name" == "$p" ]]; then
            action_text="Reinicio del Sistema"; action_class="system-reboot"; break
        fi
    done
    if [ "$action_class" == "none" ]; then
        services=$(sudo -n rpm -ql "$pkg_name" 2>/dev/null | grep '/systemd/system/.*\\.service$' | xargs -r basename | tr '\\n' ',' | sed 's/,$//')
        if [ -n "$services" ]; then
            action_text="Reinicio de Servicio: ${services//,/\\, }"; action_class="service-restart"
        fi
    fi
    
    echo "PACKAGE_DATA${DELIMITER}${pkg_full_name}${DELIMITER}${current_version}${DELIMITER}${new_version}${DELIMITER}${repo}${DELIMITER}${action_text}${DELIMITER}${action_class}"
done <<< "$updates_output"
"""

def run_remote_audit_agent(server_ip):
    """Ejecuta el agente remoto y devuelve la salida en bruto."""
    print(f"INFO: Auditando {server_ip}...")
    ssh_opts = "-o StrictHostKeyChecking=no -o ConnectTimeout=20 -o PasswordAuthentication=no"
    ssh_command = f"ssh {ssh_opts} {SSH_USER}@{server_ip}"
    try:
        result = subprocess.run(
            f"{ssh_command} 'bash -s'", input=REMOTE_AGENT_SCRIPT, shell=True, 
            capture_output=True, text=True, check=True, timeout=300
        )
        return {"ip": server_ip, "output": result.stdout}
    except Exception as e:
        error_msg = f"Fallo CRÍTICO del agente en {server_ip}.\n{getattr(e, 'stderr', str(e))}"
        return {"ip": server_ip, "error": error_msg}

def parse_and_structure_data(all_raw_data):
    """Toma la salida en bruto de todos los servidores y la estructura."""
    structured_data = []
    for data in all_raw_data:
        ip = data['ip']
        if 'error' in data:
            structured_data.append({'ip': ip, 'hostname': f"Error de conexión ({ip})", 'updates': [], 'error': data['error']})
            continue

        lines = data.get('output', '').strip().split('\n')
        if not lines: continue
        
        server_data = {'ip': ip, 'updates': []}
        for line in lines:
            if line.startswith("SERVER_INFO"):
                server_data['hostname'] = line.split("|:|:")[1]
            elif line.startswith("PACKAGE_DATA"):
                parts = line.split("|:|:")
                if len(parts) == 7:
                    _, pkg, cur_v, new_v, repo, act_txt, act_cls = parts
                    server_data['updates'].append({
                        'full_name': pkg, 'current_version': cur_v, 'new_version': new_v,
                        'repo': repo, 'action_text': act_txt, 'action_class': act_cls
                    })
        structured_data.append(server_data)
    return structured_data

def generate_html_report(all_servers_data):
    """Genera el reporte HTML final, con una sección por cada servidor."""
    # Estilo CSS del script que le gustó
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f8f9fa; color: #212529; margin: 20px; }
        h1 { text-align: center; color: #343a40; border-bottom: 3px solid #c00; padding-bottom: 10px; }
        .server-section { margin-bottom: 40px; padding: 20px; background-color: #fff; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        h2 { color: #343a40; border-bottom: 2px solid #eee; padding-bottom: 8px; }
        table { width: 100%; margin: 20px 0; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border: 1px solid #dee2e6; }
        thead tr { background-color: #34495e; color: white; }
        tbody tr:nth-of-type(even) { background-color: #f2f2f2; }
        .summary { margin: 20px 0; padding: 15px; background-color: #e9ecef; border-left: 5px solid #007bff; }
        .summary.reboot { border-left-color: #dc3545; }
        .summary.service { border-left-color: #ffc107; }
        .system-reboot { background-color: #f8d7da; color: #721c24; font-weight: bold; }
        .service-restart { background-color: #fff3cd; color: #856404; }
        .none { color: #28a745; }
        .error-block { background-color: #f8d7da; border-left-color: #dc3545; color: #721c24; white-space: pre-wrap; font-family: monospace; }
    </style>
    """
    
    server_blocks_html = []
    for server in sorted(all_servers_data, key=lambda x: x.get('hostname', '')):
        hostname, ip, updates, error = server.get('hostname'), server.get('ip'), server.get('updates', []), server.get('error')
        
        block = f"<div class='server-section'><h2>Reporte para: {hostname} ({ip})</h2>"
        
        if error:
            block += f"<div class='summary error-block'><h3>Error Crítico</h3><p>{html.escape(error)}</p></div>"
        elif not updates:
            block += "<div class='summary'><h3>Sistema Actualizado</h3><p>No se encontraron actualizaciones pendientes.</p></div>"
        else:
            # Calcular resumen para este servidor
            needs_reboot = any(u['action_class'] == 'system-reboot' for u in updates)
            needs_service = any(u['action_class'] == 'service-restart' for u in updates)
            
            summary = {}
            if needs_reboot:
                summary['text'] = "<strong>Acción Crítica:</strong> Se requiere un <strong>reinicio completo del sistema</strong>."
                summary['class'] = 'reboot'
            elif needs_service:
                summary['text'] = "Se requiere el <strong>reinicio de uno o más servicios</strong>. No es necesario un reinicio completo del sistema."
                summary['class'] = 'service'
            else:
                summary['text'] = "Las actualizaciones pendientes no requieren reinicio de sistema o servicios principales."
                summary['class'] = 'info'
            
            block += f"<div class='summary {summary['class']}'><h3>Resumen Ejecutivo</h3><p>{summary['text']}</p></div>"
            
            # Construir la tabla
            table_rows = "".join([
                f"""<tr>
                    <td>{u['full_name']}</td><td>{u['current_version']}</td>
                    <td>{u['new_version']}</td><td>{u['repo']}</td>
                    <td class="{u['action_class']}">{html.escape(u['action_text'])}</td>
                </tr>""" for u in updates
            ])
            block += f"""
            <h3>Detalle de Paquetes ({len(updates)} encontrados)</h3>
            <table><thead><tr>
                <th>Paquete</th><th>Versión Actual</th><th>Versión a Actualizar</th><th>Repositorio</th><th>Acción Requerida</th>
            </tr></thead><tbody>{table_rows}</tbody></table>
            """
        
        block += "</div>"
        server_blocks_html.append(block)

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_html = f"""
    <!DOCTYPE html><html lang="es"><head><title>Reporte de Auditoría Adaptado</title>{html_style}</head>
    <body><h1>Reporte de Auditoría de Actualizaciones RHEL</h1><p style="text-align:center;">Generado el: {report_date}</p>
    {''.join(server_blocks_html)}
    </body></html>
    """
    with open(REPORT_PATH, "w", encoding="utf-8") as f: f.write(full_html)


def main():
    all_raw_data = []
    print("Iniciando auditoría con arquitectura adaptada...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(run_remote_audit_agent, ip): ip for ip in SERVERS_TO_AUDIT}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                all_raw_data.append(future.result())
                print(f"INFO: Datos de {ip} recibidos.")
            except Exception as exc:
                all_raw_data.append({"ip": ip, "error": f"Excepción CRÍTICA en el controlador: {exc}"})
    
    print("\nRecolección de datos completada. Procesando y generando reporte HTML...")
    structured_data = parse_and_structure_data(all_raw_data)
    generate_html_report(structured_data)
    print(f"\n¡Éxito! Reporte completo guardado en: {os.path.abspath(REPORT_PATH)}")

if __name__ == "__main__":
    main()