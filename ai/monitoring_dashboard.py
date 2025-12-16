"""
Monitoring avec dashboard temps réel"""

import os
import time
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich import box
from rich.text import Text

console = Console()

def create_dashboard_vertical(stats, recent_anomalies):

    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=10),
        Layout(name="categories", size=10),
        Layout(name="anomalies", size=12),
        Layout(name="footer", size=3)
    )
    
    # Header
    header_text = Text("🐝 HIVEMIND - MONITORING DASHBOARD", style="bold cyan", justify="center")
    layout["header"].update(Panel(header_text, style="cyan"))
    
    # Section 1 : Statistiques
    stats_table = Table(show_header=False, box=box.ROUNDED, expand=True)
    stats_table.add_column("Métrique", style="cyan bold", width=25)
    stats_table.add_column("Valeur", style="yellow bold", justify="center", width=15)
    stats_table.add_column("Graphique", style="blue")
    
    stats_table.add_row("📁 Fichiers traités", f"{stats['files_processed']}", "")
    stats_table.add_row("📝 Lignes analysées", f"{stats['lines_processed']}", "")
    
    anomaly_count = stats['anomalies_detected']
    anomaly_style = "red bold" if anomaly_count > 10 else "yellow" if anomaly_count > 5 else "green"
    anomaly_bar = "█" * min(anomaly_count, 40)
    stats_table.add_row("🚨 Anomalies détectées", f"[{anomaly_style}]{anomaly_count}[/]", anomaly_bar)
    
    stats_table.add_row("⚠️  Avertissements", f"{stats['warnings']}", "")
    stats_table.add_row("❌ Erreurs", f"{stats['errors']}", "")
    
    if stats['lines_processed'] > 0:
        rate = (stats['anomalies_detected'] / stats['lines_processed']) * 100
        rate_style = "red bold" if rate > 50 else "yellow" if rate > 20 else "green"
        rate_bar = "█" * int(rate / 2)  # Échelle /2 pour tenir sur l'écran
        stats_table.add_row("📈 Taux d'anomalies", f"[{rate_style}]{rate:.1f}%[/]", rate_bar)
    
    layout["stats"].update(Panel(stats_table, title="📊 Statistiques Globales", border_style="cyan"))
    
    # Section 2 : Catégories
    cat_table = Table(show_header=True, box=box.SIMPLE, expand=True)
    cat_table.add_column("🏷️  Catégorie", style="magenta bold", width=30)
    cat_table.add_column("Count", justify="center", style="cyan bold", width=10)
    cat_table.add_column("Graphique", style="blue")
    
    for category, count in sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True)[:6]:
        bar = "█" * min(count * 2, 40)
        cat_table.add_row(category, str(count), bar)
    
    layout["categories"].update(Panel(cat_table, title="🏷️  Répartition par Catégorie", border_style="magenta"))
    
    # Section 3 : Anomalies récentes
    anomaly_table = Table(show_header=True, box=box.ROUNDED, expand=True)
    anomaly_table.add_column("", style="dim", width=3)
    anomaly_table.add_column("⏰ Heure", style="cyan", width=10)
    anomaly_table.add_column("📝 Log", style="white", width=50)
    anomaly_table.add_column("🏷️  Catégorie", style="yellow", width=20)
    
    severity_icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "none": "⚪"
    }
    
    for i, anomaly in enumerate(recent_anomalies[-5:], 1):
        icon = severity_icons.get(anomaly.get('severity', 'medium'), '🟡')
        timestamp = anomaly['timestamp'].split('T')[1][:8] if 'T' in anomaly['timestamp'] else ""
        log_text = anomaly['log'][:48] + "..." if len(anomaly['log']) > 48 else anomaly['log']
        category = anomaly['category']
        
        anomaly_table.add_row(icon, timestamp, log_text, category)
    
    layout["anomalies"].update(Panel(anomaly_table, title="🚨 Dernières Anomalies Détectées", border_style="red"))
    
    # Footer
    footer_text = Text(f"⏰ Dernière mise à jour: {datetime.now().strftime('%H:%M:%S')} | 💡 Appuyez sur Ctrl+C pour arrêter le monitoring", 
                      style="dim", justify="center")
    layout["footer"].update(Panel(footer_text, style="dim"))
    
    return layout

def monitor_results_directory(results_dir="results", refresh_interval=2):
    """Surveille avec Rich - Layout vertical"""
    
    stats = {
        'files_processed': 0,
        'lines_processed': 0,
        'anomalies_detected': 0,
        'warnings': 0,
        'errors': 0,
        'categories': defaultdict(int),
        'severity_counts': defaultdict(int)
    }
    
    recent_anomalies = []
    processed_files = set()
    
    console.print(Panel.fit("🚀 Démarrage du dashboard Rich (layout vertical)...", style="bold green"))
    time.sleep(1)
    
    try:
        with Live(create_dashboard_vertical(stats, recent_anomalies), 
                 refresh_per_second=1, console=console, screen=False) as live:
            
            while True:
                results_path = Path(results_dir)
                if not results_path.exists():
                    results_path.mkdir(exist_ok=True)
                
                json_files = list(results_path.glob("analysis_*.json"))
                
                for json_file in json_files:
                    if json_file.name not in processed_files:
                        try:
                            with open(json_file, 'r', encoding='utf-8') as f:
                                report = json.load(f)
                            
                            metadata = report.get('metadata', {})
                            statistics = report.get('statistics', {})
                            
                            stats['files_processed'] += 1
                            stats['lines_processed'] += metadata.get('total_lines', 0)
                            stats['anomalies_detected'] += statistics.get('anomalies_detected', 0)
                            stats['warnings'] += statistics.get('warnings_detected', 0)
                            
                            for anomaly in report.get('top_anomalies', []):
                                analysis = anomaly.get('analysis', {})
                                risk = analysis.get('risk_assessment', {})
                                
                                severity = risk.get('severity', 'medium')
                                if not severity or severity == 'unknown':
                                    confidence = analysis.get('confidence', 0.5)
                                    severity = 'high' if confidence >= 0.9 else 'medium' if confidence >= 0.7 else 'low'
                                
                                recent_anomalies.append({
                                    'timestamp': anomaly.get('timestamp', ''),
                                    'log': anomaly.get('original_log', '')[:100],
                                    'category': analysis.get('category', 'unknown'),
                                    'reason': analysis.get('reason', ''),
                                    'severity': severity
                                })
                                
                                category = analysis.get('category', 'unknown')
                                stats['categories'][category] += 1
                                stats['severity_counts'][severity] += 1
                            
                            processed_files.add(json_file.name)
                            
                        except Exception as e:
                            stats['errors'] += 1
                
                live.update(create_dashboard_vertical(stats, recent_anomalies))
                time.sleep(refresh_interval)
                
    except KeyboardInterrupt:
        console.print("\n")
        
        # Rapport final
        final_panel = Panel.fit(
            f"""
[cyan bold]📊 Statistiques Finales[/]

[yellow]📁 Fichiers traités:[/]     {stats['files_processed']}
[yellow]📝 Lignes analysées:[/]     {stats['lines_processed']}
[red bold]🚨 Anomalies détectées:[/]  {stats['anomalies_detected']}
[yellow]⚠️  Avertissements:[/]      {stats['warnings']}
[yellow]❌ Erreurs:[/]              {stats['errors']}
            """,
            title="✨ Monitoring terminé",
            border_style="green bold"
        )
        console.print(final_panel)

if __name__ == "__main__":
    monitor_results_directory()