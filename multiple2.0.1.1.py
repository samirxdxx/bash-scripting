#!/usr/bin/env python3
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
REPORT_PATH = "./multi_server_final_report-2.0.0.9.html"
MAX_WORKERS = 20

# --- AGENTE REMOTO v3 (CON DETECCIÓN DE SERVICIOS RESTAURADA) ---
REMOTE_AGENT_SCRIPT = """
exec 2>&1
sudo -n dnf clean all &>/dev/null || true
REBOOT_PACKAGES=("kernel" "glibc" "systemd" "dbus" "linux-firmware")

echo "---BEGIN_SERVER_INFO---"; uname -n && uname -r; echo "---EXIT_CODE---$?---"

# Obtener todas las versiones instaladas de una vez para mapeo posterior
echo "---BEGIN_INSTALLED_VERSIONS---"
rpm -qa --queryformat '%{NAME}|:|:%{VERSION}-%{RELEASE}\\n'
echo "---EXIT_CODE---$?---"

# Obtener lista de actualizaciones
echo "---BEGIN_CHECK_UPDATE---"
updates_output=$(sudo -n dnf check-update --quiet)
exit_code=$?
echo "$updates_output"
echo "---EXIT_CODE---$exit_code---"

# Si hay actualizaciones, obtener metadatos adicionales
if [ $exit_code -eq 100 ]; then
    all_pkg_names=$(echo "$updates_output" | awk '{print $1}')
    echo "---BEGIN_UPDATEINFO---"; sudo -n dnf updateinfo list -q; echo "---EXIT_CODE---$?---"
    echo "---BEGIN_REPOQUERY---"; sudo -n dnf repoquery --queryformat '%{name}.%{arch}|:|:%{buildtime}' $all_pkg_names; echo "---EXIT_CODE---$?---"
    echo "---BEGIN_SERVICE_FILES---"; for pkg in $all_pkg_names; do name_only=${pkg%%.*}; files=$(sudo -n rpm -ql $name_only 2>/dev/null | grep '/systemd/system/.*\\.service$' | xargs -r basename); if [ -n "$files" ]; then echo "$name_only|:|:$(echo $files | tr '\\n' ',')"; fi; done; echo "---EXIT_CODE---$?---"
fi
"""

def parse_raw_data(raw_output, ip):
    """Procesador Central v4 - Con Diagnóstico Integrado"""
    data = {'ip': ip, 'updates': [], 'alerts': []}
    sections = {}
    current_section = None
    for line in raw_output.splitlines():
        if line.startswith('---BEGIN_'):
            current_section = line.replace('---BEGIN_', '').replace('---', '')
            sections[current_section] = {'lines': [], 'exit_code': -1}
        elif line.startswith('---EXIT_CODE---'):
            if current_section:
                try: sections[current_section]['exit_code'] = int(line.split('---')[2])
                except (ValueError, IndexError): sections[current_section]['exit_code'] = -99
            current_section = None
        elif current_section:
            sections[current_section]['lines'].append(line)

    server_info_lines = sections.get('SERVER_INFO', {}).get('lines', [])
    data['hostname'], data['kernel'] = (server_info_lines[0], server_info_lines[1]) if len(server_info_lines) > 1 else (f"Inaccesible ({ip})", "N/A")

    check_update_data = sections.get('CHECK_UPDATE', {})
    if check_update_data.get('exit_code', -1) not in [0, 100]:
        data['alerts'].append(f"ALERTA CRÍTICA: 'dnf check-update' falló (código {check_update_data['exit_code']}). No se pueden obtener datos de actualizaciones. Salida: {' '.join(check_update_data.get('lines', []))}")
        return data
    elif check_update_data.get('exit_code', -1) == 0:
        data['updates'] = [] # Exitoso, sin actualizaciones
        return data

    for line in check_update_data.get('lines', []):
        parts = line.split()
        if len(parts) >= 3 and '.' in parts[1] and any(c.isdigit() for c in parts[1]):
            data['updates'].append({'pkg': parts[0], 'new_v': parts[1], 'repo': parts[2]})
        elif line.strip(): data['alerts'].append(f"Mensaje del sistema (DNF): {line}")

    if not data['updates']: return data

    # Mapear todos los datos adicionales
    rhsa_map, build_date_map, installed_map, service_map = {}, {}, {}, {}
    
    updateinfo_data = sections.get('UPDATEINFO', {})
    if updateinfo_data.get('exit_code', 0) == 0:
        for line in updateinfo_data.get('lines', []):
            parts = line.split(); rhsa_map[parts[2]] = parts[0] if len(parts) >= 3 else 'N/A'
    else: data['alerts'].append("Diagnóstico: Información de RHSA no disponible. Puede ser normal o indicar un problema de suscripción (RHSM).")
        
    repoquery_data = sections.get('REPOQUERY', {})
    if repoquery_data.get('exit_code', 0) == 0:
        for line in repoquery_data.get('lines', []):
            if '|:|:' in line: pkg, ts = line.split('|:|:', 1); build_date_map[pkg] = datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d") if ts.isdigit() else 'Fecha Inválida'
    else: data['alerts'].append("Diagnóstico: Fechas de compilación no disponibles. Los metadatos del repositorio pueden estar incompletos.")

    installed_data = sections.get('INSTALLED_VERSIONS', {})
    if installed_data.get('exit_code', 0) == 0:
        for line in installed_data.get('lines', []):
            if '|:|:' in line: name, ver = line.split('|:|:', 1); installed_map[name] = ver
    else: data['alerts'].append("Alerta: No se pudo obtener la lista de paquetes instalados vía RPM.")

    service_data = sections.get('SERVICE_FILES', {})
    if service_data.get('exit_code', 0) == 0:
        for line in service_data.get('lines', []):
            if '|:|:' in line: name, files = line.split('|:|:', 1); service_map[name] = files.replace(',', ', ')
            
    # Enriquecer los datos finales
    reboot_pkgs = ["kernel", "glibc", "systemd", "dbus", "linux-firmware"]
    for update in data['updates']:
        pkg_name, name_only = update['pkg'], update['pkg'].split('.')[0]
        update.update({
            'rhsa': rhsa_map.get(pkg_name, 'N/A'),
            'b_date': build_date_map.get(pkg_name, 'N/A'),
            'cur_v': installed_map.get(name_only, 'No Encontrado'),
        })
        if name_only in reboot_pkgs:
            update['act_cls'], update['act_txt'] = 'system-reboot', 'Reinicio Sistema'
        elif name_only in service_map:
            update['act_cls'], update['act_txt'] = 'service-restart', f"Reinicio Servicio: {service_map[name_only]}"
        else:
            update['act_cls'], update['act_txt'] = 'none', 'Ninguno/Otro'
            
    return data

def run_remote_audit_agent(server_ip):
    # (Sin cambios)
    print(f"INFO: Auditando {server_ip}...")
    ssh_opts = "-o StrictHostKeyChecking=no -o ConnectTimeout=20 -o PasswordAuthentication=no"
    ssh_command = f"ssh {ssh_opts} {SSH_USER}@{server_ip}"
    try:
        result = subprocess.run(f"{ssh_command} 'bash -s'", input=REMOTE_AGENT_SCRIPT, shell=True, capture_output=True, text=True, check=True, timeout=300)
        return parse_raw_data(result.stdout, server_ip)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        error_msg = f"Fallo CRÍTICO del agente. No se pudo conectar o ejecutar el script base.\n{getattr(e, 'stderr', str(e))}"
        return {'ip': server_ip, 'errors': [error_msg]}

def generate_html_report(all_servers_data):
    # (Sin cambios, el HTML se adapta al nuevo modelo de datos)
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 20px; background-color: #f4f7f6; }
        h1 { text-align: center; color: #2c3e50; border-bottom: 3px solid #c00; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 9px 12px; text-align: left; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
        thead th { background-color: #34495e; color: white; position: sticky; top: 0; z-index: 1;}
        .server-header-row td { background-color: #e8f0fe; font-weight: bold; border-top: 3px solid #34495e; }
        .alert-row td { background-color: #fef9e7; color: #856404; font-family: monospace; font-size: 0.9em; white-space: pre-wrap; }
        .no-updates-row td { background-color: #e8f8f5; color: #1abc9c; text-align: center; font-style: italic; font-weight: bold; }
        .system-reboot { font-weight: bold; color: #e74c3c; }
        .service-restart { font-weight: bold; color: #f39c12; }
    </style>
    """
    table_rows = []
    for data in sorted(all_servers_data, key=lambda x: x.get('ip', '')):
        ip, hostname, kernel, updates, alerts = data.get('ip'), data.get('hostname'), data.get('kernel'), data.get('updates', []), data.get('alerts', [])
        table_rows.append(f'<tr class="server-header-row"><td colspan="2">{hostname} ({ip})</td><td colspan="7"><strong>Kernel:</strong> {kernel}</td></tr>')
        if alerts:
            for alert in alerts: table_rows.append(f'<tr><td></td><td></td><td colspan="7" class="alert-row">{html.escape(alert)}</td></tr>')
        if not updates and not alerts: table_rows.append(f'<tr class="no-updates-row"><td colspan="9">Sistema Actualizado</td></tr>')
        for u in updates:
            table_rows.append(f"""
            <tr>
                <td></td><td></td><td>{u.get('pkg')}</td><td>{u.get('cur_v')}</td><td>{u.get('new_v')}</td>
                <td>{u.get('repo')}</td><td class="{u.get('act_cls')}">{html.escape(u.get('act_txt'))}</td>
                <td>{u.get('rhsa')}</td><td>{u.get('b_date')}</td>
            </tr>""")

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_html = f"""
    <!DOCTYPE html><html lang="es"><head><title>Reporte de Auditoría (Arquitectura de Producción)</title>{html_style}</head>
    <body><h1>Reporte de Auditoría de Actualizaciones RHEL</h1><p style="text-align:center;">Generado el: {report_date}</p>
    <table><thead><tr>
        <th>Hostname</th><th>IP</th><th>Paquete</th><th>Versión Actual</th><th>V. a Actualizar</th>
        <th>Repositorio</th><th>Acción Requerida</th><th>RHSA</th><th>Fecha de Lanzamiento (Build)</th>
    </tr></thead><tbody>{''.join(table_rows)}</tbody></table></body></html>
    """
    with open(REPORT_PATH, "w", encoding="utf-8") as f: f.write(full_html)


def main():
    # (Sin cambios)
    all_data = []
    print("Iniciando auditoría con ARQUITECTURA DE PRODUCCIÓN...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(run_remote_audit_agent, ip): ip for ip in SERVERS_TO_AUDIT}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                all_data.append(future.result())
                print(f"INFO: Datos de {ip} recibidos y procesados.")
            except Exception as exc:
                all_data.append({"ip": ip, "alerts": [f"Excepción CRÍTICA en el controlador: {exc}"]})
    print("\nRecolección de datos completada. Generando reporte HTML final...")
    generate_html_report(all_data)
    print(f"\n¡Éxito! Reporte completo guardado en: {os.path.abspath(REPORT_PATH)}")

if __name__ == "__main__":
    main()
