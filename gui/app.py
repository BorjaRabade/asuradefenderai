import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import json
from datetime import datetime
from core.analyzer import Analyzer
from core.ai_reviewer import AIReviewer

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("AsuraDefenderAI")
        self.geometry("1200x800")
        self.after(0, lambda: self.state("zoomed")) # Maximizar ventana
        
        self.analyzer = Analyzer()
        self.ai_reviewer = AIReviewer()
        self.vulnerabilities = []
        self.ai_results = {} # Map id -> ai_analysis
        
        self.setup_ui()
        
    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # ==Lateral==
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="AsuraDefenderAI", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.select_btn = ctk.CTkButton(self.sidebar_frame, text="Seleccionar Carpeta", command=self.select_folder)
        self.select_btn.grid(row=1, column=0, padx=20, pady=10)

        self.select_file_btn = ctk.CTkButton(self.sidebar_frame, text="Seleccionar Archivo", command=self.select_file)
        self.select_file_btn.grid(row=2, column=0, padx=20, pady=10)
        
        self.scan_btn = ctk.CTkButton(self.sidebar_frame, text="Iniciar Análisis", command=self.start_scan, state="disabled")
        self.scan_btn.grid(row=3, column=0, padx=20, pady=10)
        
        # Boton exportar oculto inicialmente
        self.export_btn = ctk.CTkButton(self.sidebar_frame, text="Exportar JSON", command=self.export_report, state="disabled", fg_color="green")
        self.export_btn.grid(row=4, column=0, padx=20, pady=10)
        self.export_btn.grid_remove() 
        
        # ==Principal==
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # ==Estadisticas==
        self.stats_frame = ctk.CTkFrame(self.main_frame, height=100)
        self.stats_frame.pack(fill="x", pady=(0, 20))
        
        self.lbl_total = ctk.CTkLabel(self.stats_frame, text="Total: 0", font=("Arial", 16, "bold"))
        self.lbl_total.pack(side="left", padx=20, pady=10)
        
        self.lbl_critical = ctk.CTkLabel(self.stats_frame, text="Críticas: 0", text_color="red", font=("Arial", 16))
        self.lbl_critical.pack(side="left", padx=20, pady=10)
        
        # ==Resultados==
        self.results_scroll = ctk.CTkScrollableFrame(self.main_frame, label_text="Hallazgos")
        self.results_scroll.pack(fill="both", expand=True)

        self.status_label = ctk.CTkLabel(self.main_frame, text="Listo para escanear.", anchor="w")
        self.status_label.pack(fill="x", pady=(5, 0))

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_target = folder
            self.status_label.configure(text=f"Objetivo: {folder}")
            self.scan_btn.configure(state="normal")
            self.export_btn.grid_remove()

    def select_file(self):
        file = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file:
            self.target_target = file
            self.status_label.configure(text=f"Objetivo: {file}")
            self.scan_btn.configure(state="normal")
            self.export_btn.grid_remove()
            
    def start_scan(self):
        self.scan_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.export_btn.grid_remove()
        
        self.status_label.configure(text="Escaneando... Por favor espere.")
        
        self.vulnerabilities = [] 
        self.ai_results = {}
        for widget in self.results_scroll.winfo_children():
            widget.destroy()

        threading.Thread(target=self.run_full_analysis, daemon=True).start()
        
    def run_full_analysis(self):
        try:
            # 1. Análisis Estático (Rápido)
            self.vulnerabilities = self.analyzer.analizar_target(self.target_target)
            
            # 2. Análisis IA (Automático)
            if self.vulnerabilities:
                self.update_status_safe("Analizando hallazgos con IA (Groq)...")
                
                for vuln in self.vulnerabilities:
                    vid = f"{vuln.archivo}:{vuln.linea}"
                    try:
                        analisis = self.ai_reviewer.analizar_vulnerabilidad(vuln.nombre, vuln.codigo_detectado, vuln.archivo)
                        self.ai_results[vid] = analisis
                    except Exception as e:
                        print(f"Fallo IA en {vid}: {e}")
                        # Continuamos sin IA para este item
            
            self.after(0, self.display_results)
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.after(0, lambda: self.scan_btn.configure(state="normal"))

    def update_status_safe(self, text):
        self.after(0, lambda: self.status_label.configure(text=text))

    def display_results(self):
        self.status_label.configure(text=f"Análisis completado. Encontrados {len(self.vulnerabilities)} problemas.")
        
        # Mostrar botón exportar
        if self.vulnerabilities:
            self.export_btn.grid(row=4, column=0, padx=20, pady=10)
            self.export_btn.configure(state="normal")
        
        crit = sum(1 for v in self.vulnerabilities if v.severidad == "CRITICAL")
        self.lbl_total.configure(text=f"Total: {len(self.vulnerabilities)}")
        self.lbl_critical.configure(text=f"Críticas: {crit}")
        
        for widget in self.results_scroll.winfo_children():
            widget.destroy()

        for vuln in self.vulnerabilities:
            card = ctk.CTkFrame(self.results_scroll, fg_color=("gray85", "gray25"))
            card.pack(fill="x", pady=5, padx=5)
            
            header = ctk.CTkLabel(card, text=f"[{vuln.severidad}] {vuln.nombre} - {vuln.archivo}:{vuln.linea}", 
                                  font=("Arial", 12, "bold"), anchor="w")
            header.pack(fill="x", padx=10, pady=5)
            
            code = ctk.CTkTextbox(card, height=60, font=("Consolas", 11))
            code.insert("0.0", vuln.codigo_detectado)
            code.configure(state="disabled")
            code.pack(fill="x", padx=10, pady=5)
            
            rec = ctk.CTkLabel(card, text=f"Solución: {vuln.solucion}", text_color="orange", anchor="w")
            rec.pack(fill="x", padx=10, pady=(0, 5))

            # Sección IA
            vid = f"{vuln.archivo}:{vuln.linea}"
            if vid in self.ai_results and not self.ai_results[vid].startswith("Error"):
                ai_frame = ctk.CTkFrame(card, fg_color="transparent", border_width=1, border_color="purple")
                ai_frame.pack(fill="x", padx=10, pady=5)
                
                ai_lbl = ctk.CTkLabel(ai_frame, text="🤖 Análisis IA:", text_color="purple", font=("Arial", 11, "bold"), anchor="w")
                ai_lbl.pack(fill="x", padx=5, pady=2)
                
                ai_text = ctk.CTkLabel(ai_frame, text=self.ai_results[vid], wraplength=1000, justify="left", anchor="w")
                ai_text.pack(fill="x", padx=5, pady=2)

    def export_report(self):
        # Ya tenemos los datos de IA (o no, si falló)
        self.save_json_file()

    def save_json_file(self):
        try:
            filename = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            hallazgos_export = []
            for v in self.vulnerabilities:
                d = v.to_dict()
                vid = f"{v.archivo}:{v.linea}"
                
                # Logic: Si existe resultado IA y NO es un mensaje de error, lo incluimos.
                if vid in self.ai_results:
                    ai_text = self.ai_results[vid]
                    if not ai_text.startswith("Error"):
                        d["analisis_ia"] = ai_text
                        
                hallazgos_export.append(d)

            data = {
                "fecha": str(datetime.now()),
                "target": self.target_target,
                "hallazgos": hallazgos_export
            }
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
            messagebox.showinfo("Éxito", f"Reporte guardado como {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el reporte: {e}")
        finally:
            # Restaurar estado UI
            self.status_label.configure(text="Exportación completada.")
            self.scan_btn.configure(state="normal")
            
            # Actualizamos la vista por si hubo análisis nuevos
            self.display_results()

if __name__ == "__main__":
    app = App()
    app.mainloop()