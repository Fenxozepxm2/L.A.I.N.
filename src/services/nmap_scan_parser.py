from typing import List, Dict

from pydantic_models.models import NmapHostReport, NmapPortInfo, ScanAuditSummary



def parse_nmap_results(scan_results: List[Dict]) -> ScanAuditSummary:
    """
    Парсит сырые результаты сканирования Nmap и упаковывает важную информацию в Pydantic модели.
    """
    hosts_reports = []
    total_elapsed = 0.0
    total_hosts_count = 0
    up_hosts_count = 0

    for res in scan_results:
        # Собираем глобальную статистику nmap по текущему скану
        nmap_meta = res.get("nmap", {})
        stats = nmap_meta.get("scanstats", {})
        
        total_elapsed += float(stats.get("elapsed", 0))
        total_hosts_count += int(stats.get("totalhosts", 0))
        up_hosts_count += int(stats.get("uphosts", 0))

        # Переходим к парсингу хостов
        scan_data = res.get("scan", {})
        for ip, host_info in scan_data.items():
            # Извлекаем имена хостов
            names = [h.get("name") for h in host_info.get("hostnames", []) if h.get("name")]
            status = host_info.get("status", {}).get("state", "unknown")
            
            open_ports = []
            all_ports = []
            
            # Парсим секцию TCP портов
            tcp_ports = host_info.get("tcp", {})
            for port_num, port_data in tcp_ports.items():
                # Создаем объект информации о порте
                port_obj = NmapPortInfo(
                    port=int(port_num),
                    state=port_data.get("state", "unknown"),
                    reason=port_data.get("reason", ""),
                    name=port_data.get("name", ""),
                    product=port_data.get("product", ""),
                    version=port_data.get("version", ""),
                    extrainfo=port_data.get("extrainfo", ""),
                    cpe=port_data.get("cpe", "")
                )
                
                all_ports.append(port_obj)
                if port_obj.state == "open":
                    open_ports.append(port_obj)
            
            # Формируем отчет по конкретному хосту
            host_report = NmapHostReport(
                ip=ip,
                status=status,
                hostnames=names,
                open_ports=open_ports,
                all_ports=all_ports
            )
            hosts_reports.append(host_report)

    return ScanAuditSummary(
        elapsed_time=total_elapsed,
        total_hosts=total_hosts_count,
        up_hosts=up_hosts_count,
        hosts=hosts_reports
    )
