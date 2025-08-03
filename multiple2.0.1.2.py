#!/usr/bin/env python3
# ==============================================================================
# final_localhost_aware_audit.py
#
# Descripción:
#   Versión final con conciencia de localidad. Detecta si la IP a auditar
#   pertenece al host local y ejecuta los comandos directamente, evitando SSH.
#   Esto soluciona el error 'Permission denied' para el host local y optimiza
#   su auditoría.
# ==============================================================================
import subprocess
import os
import sys
from datetime import datetime
import html
import concurrent.futures
import socket # Necesario para obtener las IPs locales

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
REPORT_PATH = "./multi_server_final_flat_report.html"
MAX_WORKERS = 20

# --- AGENTE REMOTO (Sin cambios) ---
REMOTE_AGENT_SCRIPT = """
set -o pipefail
REBOOT_PACKAGES=("kernel" "glibc" "systemd" "dbus" "linux-firmware")
DELIMITER="|:|:"
echo "SERVER_INFO${DELIMITER}$(uname -n)"
updates_output=$(sudo -n dnf check-update --quiet 2>/dev/null || true)
if [ -z "$updates_output" ]; then exit 0; fi
while read -r line; do
    if [[ "$line" == "Last metadata expiration check:"* ]] || [[ -z "$line" ]]; then continue; fi
    pkg_full_name=$(echo "$line" | awk '{print $1}'); new_version=$(echo "$line" | awk '{print $2}'); repo=$(echo "$line" | awk '{print $3}'); pkg_name=${pkg_full_name%%.*}
    current_version=$(sudo -n rpm -q "$pkg_name" --queryformat '%{VERSION}-%{RELEASE}' 2>/dev/null || echo "No instalado")
    action_text="Ninguno/Otro"; action_class="none"
    for p in "${REBOOT_PACKAGES[@]}"; do
        if [[ "$pkg_name" == "$p" ]]; then action_text="Reinicio Sistema"; action_class="system-reboot"; break; fi
    done
    if [ "$action_class" == "none" ]; then
        services=$(sudo -n rpm -ql "$pkg_name" 2>/dev/null | grep '/systemd/system/.*\\.service$' | xargs -r basename | tr '\\n' ',' | sed 's/,$//')
        if [ -n "$services" ]; then action_text="Reinicio Servicio: ${services//,/\\, }"; action_class="service-restart"; fi
    fi
    echo "PACKAGE_DATA${DELIMITER}${pkg_full_name}${DELIMITER}${current_version}${DELIMITER}${new_version}${DELIMITER}${repo}${DELIMITER}${action_text}${DELIMITER}${action_class}"
done <<< "$updates_output"
"""

def get_local_ips():
    """Obtiene una lista de todas las direcciones IP de la máquina local."""
    ips = set(['127.0.0.1', 'localhost'])
    try:
        # Esto obtiene IPs de todas las interfaces de red
        output = subprocess.check_output(['hostname', '-I']).decode('utf-8').strip()
        ips.update(output.split())
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback si 'hostname -I' no funciona
        try:
            hostname = socket.gethostname()
            ips.add(hostname)
            ips.add(socket.gethostbyname(hostname))
        except socket.gaierror:
            pass # No se pudo resolver el hostname
    return ips

def run_audit(server_ip, local_ips):
    """Función de auditoría unificada que decide si usar SSH o ejecución local."""
    if server_ip in local_ips:
        print(f"INFO: Auditando host local ({server_ip}) directamente...")
        command = ['bash', '-c', REMOTE_AGENT_SCRIPT]
    else:
        print(f"INFO: Auditando host remoto ({server_ip}) vía SSH...")
        ssh_command = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=20 -o PasswordAuthentication=no {SSH_USER}@{server_ip} 'bash -s'"
        command = ['bash', '-c', ssh_command]
    
    try:
        # Usamos un solo bloque try/except para ambos casos
        # Nota: La ejecución local usa 'shell=False' y pasa el comando como lista
        # La ejecución remota debe usar 'shell=True'
        if server_ip in local_ips:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        else:
             # Para la ejecución remota, pasamos el script como input a `bash -s`
             result = subprocess.run(
                ['bash', '-c', f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=20 -o PasswordAuthentication=no {SSH_USER}@{server_ip} 'bash -s'"],
                input=REMOTE_AGENT_SCRIPT, capture_output=True, text=True, check=True, timeout=300
             )
        return {"ip": server_ip, "output": result.stdout}
    except Exception as e:
        error_msg = f"Fallo CRÍTICO del agente en {server_ip}.\n{getattr(e, 'stderr', str(e))}"
        return {"ip": server_ip, "error": error_msg}


def parse_and_structure_data(all_raw_data):
    # (Sin cambios)
    structured_data = []
    for data in all_raw_data:
        ip, error = data.get('ip'), data.get('error')
        if error:
            structured_data.append({'ip': ip, 'hostname': f"Error", 'updates': [], 'error': error})
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
                        'pkg': pkg, 'cur_v': cur_v, 'new_v': new_v,
                        'repo': repo, 'act_txt': act_txt, 'act_cls': act_cls
                    })
        structured_data.append(server_data)
    return structured_data

def generate_html_report(all_servers_data):
    # (Sin cambios)
    html_style = """ ... """ # Omitido por brevedad
    # ...
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }
        h1 { text-align: center; color: #2c3e50; border-bottom: 3px solid #c00; padding-bottom: 10px; }
        .table-container { max-height: 80vh; overflow-y: auto; border: 1px solid #dee2e6; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 9px 12px; text-align: left; border: 1px solid #e0e0e0; vertical-align: top; }
        thead th { background-color: #34495e; color: white; position: sticky; top: 0; z-index: 1; }
        .no-updates-row td { background-color: #e8f8f5; color: #1abc9c; font-weight: bold; }
        .error-row td { background-color: #f8d7da; color: #721c24; font-family: monospace; white-space: pre-wrap; }
        .system-reboot { background-color: #f8d7da !important; }
        .service-restart { background-color: #fff3cd !important; }
        tbody tr:nth-of-type(even) { background-color: #f2f2f2; }
    </style>
    """
    
    table_rows = []
    for server in sorted(all_servers_data, key=lambda x: x.get('hostname', 'zzzz')):
        hostname, ip, updates, error = server.get('hostname'), server.get('ip'), server.get('updates', []), server.get('error')

        if error:
            table_rows.append(f'<tr class="error-row"><td colspan="2">{hostname} ({ip})</td><td colspan="5">{html.escape(error)}</td></tr>')
            continue
        
        if not updates:
            table_rows.append(f'<tr class="no-updates-row"><td>{hostname}</td><td>{ip}</td><td colspan="5">Sistema Actualizado</td></tr>')
        else:
            for u in updates:
                action_cell = f'<td class="{u.get("act_cls")}">{html.escape(u.get("act_txt"))}</td>'
                table_rows.append(f"""
                <tr>
                    <td>{hostname}</td><td>{ip}</td>
                    <td>{u.get('pkg')}</td><td>{u.get('cur_v')}</td><td>{u.get('new_v')}</td>
                    <td>{u.get('repo')}</td>{action_cell}
                </tr>""")

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_html = f"""
    <!DOCTYPE html><html lang="es"><head><title>Reporte de Auditoría Final</title>{html_style}</head>
    <body>
        <h1>Reporte de Auditoría de Actualizaciones RHEL</h1>
        <p style="text-align:center;">Generado el: {report_date}</p>
        <div class="table-container"><table>
            <thead><tr>
                <th>Hostname</th><th>IP</th><th>Paquete</th><th>Versión Actual</th><th>V. a Actualizar</th>
                <th>Repositorio</th><th>Acción Requerida</th>
            </tr></thead>
            <tbody>{''.join(table_rows)}</tbody>
        </table></div>
    </body></html>
    """
    with open(REPORT_PATH, "w", encoding="utf-8") as f: f.write(full_html)


def main():
    # Obtener las IPs locales ANTES de iniciar los hilos
    local_ips = get_local_ips()
    print(f"INFO: IPs locales detectadas: {local_ips}")
    
    all_raw_data = []
    print("Iniciando auditoría final con conciencia de localidad...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Pasar el conjunto de IPs locales a cada llamada
        future_to_ip = {executor.submit(run_audit, ip, local_ips): ip for ip in SERVERS_TO_AUDIT}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                all_raw_data.append(future.result())
                print(f"INFO: Datos de {ip} recibidos.")
            except Exception as exc:
                all_raw_data.append({"ip": ip, "error": f"Excepción CRÍTICA en el controlador: {exc}"})
    
    print("\nRecolección de datos completada. Procesando y generando reporte HTML final...")
    structured_data = parse_and_structure_data(all_raw_data)
    generate_html_report(structured_data)
    print(f"\n¡Éxito! Reporte completo guardado en: {os.path.abspath(REPORT_PATH)}")

if __name__ == "__main__":
    main()