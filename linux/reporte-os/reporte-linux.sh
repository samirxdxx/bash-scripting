#!/bin/bash
# ==============================================================================
# UNIFIED REPORT SCRIPT - DevSecOps Architect Version
#
# Fusiona la recolección de datos y la generación de reportes HTML en un
# único script atómico.
#
# Mejoras clave:
#   - Sin archivos de texto intermedios.
#   - Uso de acordeones (<details>/<summary>) para una UX limpia.
#   - Las etiquetas de contexto (#etiqueta) se convierten en títulos de acordeón.
#   - Función 'generate_accordion' para modularidad y mantenibilidad.
# ==============================================================================

# --- CONFIGURACIÓN ---
OUTPUT_HTML="$(hostname)_report_$(date +%Y%m%d).html"

# --- FUNCIÓN DE AYUDA PARA GENERACIÓN DE CONTENIDO ---
# Uso: generate_accordion "Título del Acordeón" "comando a ejecutar"
# Ejecuta un comando, captura su salida (stdout y stderr) y la envuelve
# en una estructura de acordeón HTML.
generate_accordion() {
  local title="$1"
  local command_str="$2"
  
  echo "<details class='accordion'>"
  echo "  <summary>$title</summary>"
  echo "  <pre>"
  
  # Ejecuta el comando y captura su salida. El '|| true' evita que el script
  # se detenga si un comando falla (set -e).
  # '2>&1' redirige stderr a stdout para capturar errores también.
  output=$(eval "$command_str" 2>&1) || true
  
  if [[ -n "$output" ]]; then
    # Escapamos caracteres HTML para evitar romper el renderizado
    printf '%s' "$output" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
  else
    echo "No se obtuvo información o el comando no aplicó."
  fi
  
  echo "  </pre>"
  echo "</details>"
}


# ==============================================================================
# INICIO DE LA GENERACIÓN DEL DOCUMENTO HTML
# ==============================================================================
cat <<EOF > "$OUTPUT_HTML"
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reporte de Servidor: $(hostname)</title>
  <style>
    body { font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif; margin: 0; background-color: #f0f2f5; color: #1c1e21; }
    .header { display: flex; justify-content: space-between; align-items: center; background-color: #2c3e50; color: white; padding: 10px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .header img { max-height: 40px; }
    .header h1 { margin: 0; font-size: 1.4rem; font-weight: 300; }
    .header p { margin: 5px 0 0; font-size: 0.8rem; color: #bdc3c7; }
    .tab { display: flex; flex-wrap: wrap; background-color: #34495e; }
    .tab button { background-color: transparent; color: #ecf0f1; border: none; padding: 14px 16px; cursor: pointer; font-size: 0.9em; transition: background-color 0.3s, color 0.3s; border-bottom: 3px solid transparent; }
    .tab button:hover { background-color: #46627f; }
    .tab button.active { color: #ffffff; font-weight: 600; border-bottom: 3px solid #e67e22; }
    .tabcontent { display: none; padding: 20px; }
    .subtab { display: flex; border-bottom: 1px solid #dfe3e8; margin-bottom: 15px; }
    .subtab button { background: #f0f2f5; color: #34495e; border: none; padding: 10px 15px; cursor: pointer; transition: background-color 0.3s; border-radius: 5px 5px 0 0; margin-right: 5px; }
    .subtab button.active { background-color: #ffffff; color: #2c3e50; font-weight: bold; border-top: 1px solid #dfe3e8; border-left: 1px solid #dfe3e8; border-right: 1px solid #dfe3e8; }
    .subtabcontent { display: none; padding: 15px; background-color: #ffffff; border: 1px solid #dfe3e8; border-top: none; border-radius: 0 0 5px 5px; }
    
    /* Estilos para el acordeón */
    .accordion { border: 1px solid #dfe3e8; border-radius: 5px; margin-bottom: 10px; background: #fafbfc; }
    .accordion summary { font-weight: 600; cursor: pointer; padding: 10px 15px; color: #2c3e50; background: #f6f8fa; border-radius: 5px 5px 0 0; user-select: none; }
    .accordion summary:hover { background-color: #eef1f4; }
    .accordion[open] > summary { border-bottom: 1px solid #dfe3e8; }
    .accordion pre { background-color: #ffffff; padding: 15px; margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', 'Menlo', 'Monaco', monospace; font-size: 0.85em; color: #333; border-radius: 0 0 5px 5px; }

    @media (max-width: 768px) {
        .tab { flex-direction: column; }
    }
  </style>
  <script>
    function openTab(evt, tabName) {
      let i, tabcontent, tablinks;
      tabcontent = document.getElementsByClassName("tabcontent");
      for (i = 0; i < tabcontent.length; i++) tabcontent[i].style.display = "none";
      tablinks = document.getElementsByClassName("tablinks");
      for (i = 0; i < tablinks.length; i++) tablinks[i].className = tablinks[i].className.replace(" active", "");
      document.getElementById(tabName).style.display = "block";
      evt.currentTarget.className += " active";
    }
    function openSubTab(evt, subTabId, parentTabId) {
      let i, subtabcontent, subtablinks;
      subtabcontent = document.getElementById(parentTabId).getElementsByClassName("subtabcontent");
      for (i = 0; i < subtabcontent.length; i++) subtabcontent[i].style.display = "none";
      subtablinks = document.getElementById(parentTabId).getElementsByClassName("subtablinks");
      for (i = 0; i < subtablinks.length; i++) subtablinks[i].className = subtablinks[i].className.replace(" active", "");
      document.getElementById(subTabId).style.display = "block";
      evt.currentTarget.className += " active";
    }
    document.addEventListener("DOMContentLoaded", () => {
      // Abre la primera pestaña por defecto
      document.querySelector(".tablinks").click();
      // Abre la primera subpestaña de cada pestaña principal
      document.querySelectorAll(".tabcontent").forEach(tab => {
        const firstSubTab = tab.querySelector(".subtablinks");
        if(firstSubTab) firstSubTab.click();
      });
    });
  </script>
</head>
<body>
  <div class="header">
    <h1>Reporte de Servidor: $(hostname)<p>Generado el: $(date +"%Y-%m-%d %H:%M:%S")</p></h1>
    <img src="https://www.nuamx.com/logo.svg" alt="Logo">
  </div>

  <!-- Barra de Pestañas Principales -->
  <div class="tab">
    <button class='tablinks' onclick="openTab(event, 'Datos_Generales')">Datos Generales</button>
    <button class='tablinks' onclick="openTab(event, 'Configuracion_ETC')">Configuración ETC</button>
    <button class='tablinks' onclick="openTab(event, 'Recursos')">Recursos</button>
    <button class='tablinks' onclick="openTab(event, 'Redes')">Redes</button>
    <button class='tablinks' onclick="openTab(event, 'Seguridad')">Seguridad</button>
    <button class='tablinks' onclick="openTab(event, 'RPM')">RPM</button>
    <button class='tablinks' onclick="openTab(event, 'Servicios')">Servicios</button>
    <button class='tablinks' onclick="openTab(event, 'Usuarios_y_Grupos')">Usuarios y Grupos</button>
    <button class='tablinks' onclick="openTab(event, 'Contenedores')">Contenedores</button>
  </div>
EOF

# ==============================================================================
# SECCIÓN: DATOS GENERALES
# ==============================================================================
(
cat <<'EOT'
<div id='Datos_Generales' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'DG_Resumen', 'Datos_Generales')">Resumen</button>
    <button class="subtablinks" onclick="openSubTab(event, 'DG_Creacion', 'Datos_Generales')">Creación del Servidor</button>
  </div>
  
  <div id="DG_Resumen" class="subtabcontent">
EOT
generate_accordion "Nombre de Servidor" "hostname"
generate_accordion "Dirección IP" "ip a | grep -i inet"
generate_accordion "Versión de Sistema Operativo" "cat /etc/system-release"
generate_accordion "Versión de Kernel" "uname -srm"
generate_accordion "Carga del Sistema (Uptime)" "uptime"
cat <<'EOT'
  </div>
  
  <div id="DG_Creacion" class="subtabcontent">
EOT
generate_accordion "Fecha de creación (redhat-release)" "ls -lct /etc | grep redhat-release"
generate_accordion "Fecha de creación (logs anaconda)" "ls -lt /var/log/anaconda/"
generate_accordion "Fecha de creación del sistema de archivos raíz" "tune2fs -l \$(df / | tail -1 | awk '{print \$1}') | grep 'Filesystem created'"
generate_accordion "Fecha del primer registro del sistema (journalctl)" "journalctl --list-boots | head -1"
generate_accordion "Fecha de instalación del paquete 'basesystem'" "rpm -qi basesystem | grep Install"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# ==============================================================================
# SECCIÓN: CONFIGURACIÓN ETC
# ==============================================================================
(
cat <<'EOT'
<div id='Configuracion_ETC' class='tabcontent'>
  <div class="subtab"><button class="subtablinks" onclick="openSubTab(event, 'CFG_All', 'Configuracion_ETC')">Archivos de Configuración</button></div>
  <div id="CFG_All" class="subtabcontent">
EOT
generate_accordion "/etc/exports" "grep -v '^#\|^$' /etc/exports"
generate_accordion "/etc/hosts" "grep -v '^#\|^$' /etc/hosts"
generate_accordion "/etc/ssh/sshd_config" "grep -v '^#\|^$' /etc/ssh/sshd_config"
generate_accordion "/etc/ntp.conf" "grep -v '^#\|^$' /etc/ntp.conf"
generate_accordion "/etc/chrony.conf" "grep -v '^#\|^$' /etc/chrony.conf"
generate_accordion "/etc/rancher/rke2/config.yaml" "grep -v '^#\|^$' /etc/rancher/rke2/config.yaml"
generate_accordion "/etc/zabbix/zabbix_agent2.conf" "grep -v '^#\|^$' /etc/zabbix/zabbix_agent2.conf"
generate_accordion "/etc/default/grub" "grep -v '^#\|^$' /etc/default/grub"
generate_accordion "/etc/nsswitch.conf" "grep -v '^#\|^$' /etc/nsswitch.conf"
generate_accordion "/etc/systemd/logind.conf" "grep -v '^#\|^$' /etc/systemd/logind.conf"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# ==============================================================================
# SECCIÓN: RECURSOS
# ==============================================================================
(
cat <<'EOT'
<div id='Recursos' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'RC_Almacenamiento', 'Recursos')">Almacenamiento</button>
    <button class="subtablinks" onclick="openSubTab(event, 'RC_Hardware', 'Recursos')">CPU y Memoria</button>
    <button class="subtablinks" onclick="openSubTab(event, 'RC_Procesos', 'Recursos')">Procesos</button>
  </div>
  <div id="RC_Almacenamiento" class="subtabcontent">
EOT
generate_accordion "Datos de disco (lsblk)" "lsblk -fm"
generate_accordion "Discos y su tamaño (df)" "df -hT"
generate_accordion "Espacio de inodos" "df -i"
generate_accordion "Unidades montadas (/proc/mounts)" "column -t /proc/mounts"
generate_accordion "Listado de discos y su tipo" "lsblk -d -o NAME,MODEL,SIZE,TYPE,TRAN"
generate_accordion "Dispositivos SCSI conectados" "command -v lsscsi &>/dev/null && lsscsi || echo 'lsscsi no instalado.'"
generate_accordion "Validación de Multipath" "command -v multipath &>/dev/null && multipath -ll || echo 'multipath no instalado.'"
generate_accordion "Adaptadores de bus host (HBA)" 'if [ -d /sys/class/fc_host ]; then for host in /sys/class/fc_host/host*; do echo "HBA: $(basename $host)"; cat $host/port_name; done; else echo "No se detectaron adaptadores HBA."; fi'
cat <<'EOT'
  </div>
  <div id="RC_Hardware" class="subtabcontent">
EOT
generate_accordion "Memoria RAM (GB)" "free -g"
generate_accordion "Memoria SWAP" "swapon --show"
generate_accordion "Información de CPU" "lscpu"
cat <<'EOT'
  </div>
  <div id="RC_Procesos" class="subtabcontent">
EOT
generate_accordion "Top 50 procesos por uso de CPU" "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 50"
generate_accordion "Top 50 procesos por uso de memoria" "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 50"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# ==============================================================================
# SECCIÓN: REDES
# ==============================================================================
(
cat <<'EOT'
<div id='Redes' class='tabcontent'>
  <div class="subtab"><button class="subtablinks" onclick="openSubTab(event, 'NET_All', 'Redes')">Configuración de Red</button></div>
  <div id="NET_All" class="subtabcontent">
EOT
generate_accordion "Resolución de DNS (/etc/resolv.conf)" "cat /etc/resolv.conf"
generate_accordion "Tabla de ruteo" "ip route"
generate_accordion "Puertos activos" "if command -v netstat &>/dev/null; then netstat -tulnpe; else ss -tulnpe; fi"
generate_accordion "Estado de las Interfaces de Red" "ip -s link"
generate_accordion "Conexiones activas (NetworkManager)" "nmcli connection show --active"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# ==============================================================================
# SECCIÓN: SEGURIDAD
# ==============================================================================
(
cat <<'EOT'
<div id='Seguridad' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'SEC_SELinux', 'Seguridad')">SELinux</button>
    <button class="subtablinks" onclick="openSubTab(event, 'SEC_Firewall', 'Seguridad')">Firewall</button>
    <button class="subtablinks" onclick="openSubTab(event, 'SEC_SSH', 'Seguridad')">Conexiones SSH</button>
    <button class="subtablinks" onclick="openSubTab(event, 'SEC_Logs', 'Seguridad')">Logs Críticos</button>
  </div>
  <div id="SEC_SELinux" class="subtabcontent">
EOT
generate_accordion "Estado de SELinux" "sestatus"
generate_accordion "SELinux Booleans habilitados" "semanage boolean -l | grep '(on   ,   on)'"
generate_accordion "Logs de auditoría SELinux (AVC - hoy)" "ausearch -m avc -ts today 2>/dev/null | audit2allow"
cat <<'EOT'
  </div>
  <div id="SEC_Firewall" class="subtabcontent">
EOT
generate_accordion "Estado del firewall (firewalld)" "systemctl status firewalld"
generate_accordion "Reglas activas del firewall" "firewall-cmd --list-all"
cat <<'EOT'
  </div>
  <div id="SEC_SSH" class="subtabcontent">
EOT
generate_accordion "Últimas 50 Conexiones SSH/SFTP (excl. 172.16.8.38)" "grep -E 'sshd.*(Accepted|session)' /var/log/secure | grep -v '172.16.8.38' | tail -n 50"
generate_accordion "Configuración SSH por Usuario" 'for user in $(awk -F: '\''($3 >= 1000 || $1 == "root") && $1 != "nfsnobody" {print $1}'\'' /etc/passwd); do home_dir=$(eval echo ~$user); ssh_dir="$home_dir/.ssh"; if [ -d "$ssh_dir" ]; then echo "--- Usuario: $user ---"; ls -la $ssh_dir; if [ -f "$ssh_dir/authorized_keys" ]; then echo "authorized_keys:"; cat "$ssh_dir/authorized_keys"; fi; fi; done'
cat <<'EOT'
  </div>
  <div id="SEC_Logs" class="subtabcontent">
EOT
generate_accordion "Últimos 20 mensajes críticos en logs del sistema" "journalctl -p err -n 20"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# ==============================================================================
# Continuar con el resto de secciones (RPM, Servicios, Usuarios, Contenedores)
# siguiendo el mismo patrón...
# Por brevedad, se omite el resto del código, pero la estructura sería idéntica.
# ==============================================================================

# --- RPM ---
(
cat <<'EOT'
<div id='RPM' class='tabcontent'>
  <div class="subtab"><button class="subtablinks" onclick="openSubTab(event, 'RPM_All', 'RPM')">Gestión de Paquetes</button></div>
  <div id="RPM_All" class="subtabcontent">
EOT
generate_accordion "Repositorios activos" "yum repolist enabled"
generate_accordion "Paquetes pendientes de actualización" "yum check-update"
generate_accordion "Actualizaciones de seguridad pendientes" "yum updateinfo list security"
generate_accordion "Historial de actualizaciones (yum)" "yum history"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# --- SERVICIOS ---
(
cat <<'EOT'
<div id='Servicios' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'SRV_Estado', 'Servicios')">Estado</button>
    <button class="subtablinks" onclick="openSubTab(event, 'SRV_Crons', 'Servicios')">Crontabs</button>
    <button class="subtablinks" onclick="openSubTab(event, 'SRV_Time', 'Servicios')">Sincronización de Tiempo</button>
  </div>
  <div id="SRV_Estado" class="subtabcontent">
EOT
generate_accordion "Servicios activos y en ejecución" "systemctl list-units --type=service --state=running"
generate_accordion "Servicios fallidos" "systemctl --failed"
cat <<'EOT'
  </div>
  <div id="SRV_Crons" class="subtabcontent">
EOT
generate_accordion "Crontabs por usuario" 'for user in $(cut -f1 -d: /etc/passwd); do if crontab -u $user -l &>/dev/null; then echo "--- Crontab: $user ---"; crontab -u $user -l; echo ""; fi; done'
generate_accordion "Crontab del sistema (/etc/crontab)" "cat /etc/crontab"
cat <<'EOT'
  </div>
  <div id="SRV_Time" class="subtabcontent">
EOT
generate_accordion "Estado de Sincronización de Tiempo (Chrony/NTP)" "if rpm -q chrony &>/dev/null; then echo '--- Chrony ---'; systemctl status chronyd; chronyc sources; chronyc tracking; elif rpm -q ntp &>/dev/null; then echo '--- NTP ---'; systemctl status ntpd; ntpq -p; else echo 'Ni Chrony ni NTP están instalados.'; fi"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# --- USUARIOS Y GRUPOS ---
(
cat <<'EOT'
<div id='Usuarios_y_Grupos' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'UG_Cuentas', 'Usuarios_y_Grupos')">Cuentas</button>
    <button class="subtablinks" onclick="openSubTab(event, 'UG_Limites', 'Usuarios_y_Grupos')">Límites</button>
  </div>
  <div id="UG_Cuentas" class="subtabcontent">
EOT
generate_accordion "Usuarios creados manualmente (UID >= 1000)" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1, \$3, \$7}' /etc/passwd | column -t"
generate_accordion "Grupos creados manualmente (GID >= 1000)" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1, \$3}' /etc/group | column -t"
generate_accordion "Configuración de Sudoers" "grep -E '^%|^[^#]' /etc/sudoers | grep -v '^Defaults'"
generate_accordion "Miembros de los grupos 'sudo' y 'wheel'" "echo 'Grupo sudo:'; getent group sudo; echo 'Grupo wheel:'; getent group wheel"
cat <<'EOT'
  </div>
  <div id="UG_Limites" class="subtabcontent">
EOT
generate_accordion "Límites de sistema (ulimit)" "ulimit -a"
generate_accordion "Configuración de Límites (/etc/security/limits.conf y limits.d)" "cat /etc/security/limits.conf | grep -v '^#'; for f in /etc/security/limits.d/*; do echo --- \$f ---; cat \$f | grep -v '^#'; done"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"

# --- CONTENEDORES ---
(
cat <<'EOT'
<div id='Contenedores' class='tabcontent'>
  <div class="subtab">
    <button class="subtablinks" onclick="openSubTab(event, 'CON_K8S', 'Contenedores')">Kubernetes</button>
    <button class="subtablinks" onclick="openSubTab(event, 'CON_Docker', 'Contenedores')">Docker</button>
    <button class="subtablinks" onclick="openSubTab(event, 'CON_Podman', 'Contenedores')">Podman</button>
  </div>
  <div id="CON_K8S" class="subtabcontent">
EOT
generate_accordion "Estado de Nodos (kubectl)" "kubectl get nodes -o wide"
generate_accordion "Consumo de recursos por Pods (kubectl top)" "kubectl top pods -A"
generate_accordion "Pods con errores o pendientes (kubectl)" "kubectl get pods -A --field-selector=status.phase!=Running"
generate_accordion "Eventos recientes del clúster (kubectl)" "kubectl get events -A --sort-by=.metadata.creationTimestamp | tail -50"
cat <<'EOT'
  </div>
  <div id="CON_Docker" class="subtabcontent">
EOT
generate_accordion "Contenedores Docker activos" "docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'"
generate_accordion "Estadísticas de contenedores Docker" "docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'"
cat <<'EOT'
  </div>
  <div id="CON_Podman" class="subtabcontent">
EOT
generate_accordion "Contenedores Podman activos" "podman ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'"
generate_accordion "Estadísticas de contenedores Podman" "podman stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'"
cat <<'EOT'
  </div>
</div>
EOT
) >> "$OUTPUT_HTML"


# --- FINALIZACIÓN DEL DOCUMENTO ---
echo "</body></html>" >> "$OUTPUT_HTML"

echo "Reporte unificado y mejorado generado en: $OUTPUT_HTML"