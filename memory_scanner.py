#!/usr/bin/env python3

import os
import psutil
import ctypes
import time
from shellcode_detector import ShellcodeDetector

class MemoryScanner:
    
    def __init__(self):
        self.detector = ShellcodeDetector()
        self.running = False
        
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.has_memory_access = True
        except:
            self.has_memory_access = False
    
    def read_process_memory(self, pid, size=32768):
        if not self.has_memory_access:
            return None
            
        try:
            handle = self.kernel32.OpenProcess(0x0410, False, pid)
            if not handle:
                return None
            
            # Essayer différentes adresses de base
            addresses = [0x400000, 0x10000000, 0x00010000]
            
            for addr in addresses:
                buffer = ctypes.create_string_buffer(size)
                read = ctypes.c_size_t(0)
                
                success = self.kernel32.ReadProcessMemory(
                    handle, addr, buffer, size, ctypes.byref(read)
                )
                
                if success and read.value > 1000:
                    self.kernel32.CloseHandle(handle)
                    return buffer.raw[:read.value]
            
            self.kernel32.CloseHandle(handle)
            
        except:
            pass
        
        return None
    
    def scan_process(self, proc):
        try:
            pid = proc.pid
            name = proc.name()
            
            # Ignorer les processus système
            if name in ['System', 'csrss.exe', 'svchost.exe', 'winlogon.exe']:
                return None
            
            memory_data = self.read_process_memory(pid)
            if not memory_data:
                return None
            
            result = self.detector.analyze(memory_data)
            
            if result['is_malicious']:
                return {
                    'pid': pid,
                    'name': name,
                    'analysis': result
                }
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass
        
        return None
    
    def scan_all_processes(self):
        print("Démarrage de l'analyse mémoire...")
        
        detections = []
        scanned = 0
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                result = self.scan_process(proc)
                scanned += 1
                
                if result:
                    detections.append(result)
                    self.print_detection(result)
                
                if scanned % 50 == 0:
                    print(f"Analysés: {scanned} processus")
                    
            except KeyboardInterrupt:
                print("\nAnalyse interrompue")
                break
            except:
                continue
        
        print(f"\nAnalyse terminée. Processus: {scanned}, Détections: {len(detections)}")
        return detections
    
    def print_detection(self, result):
        analysis = result['analysis']
        
        print(f"\n[DÉTECTION] {result['name']} (PID: {result['pid']})")
        print(f"Score de Risque: {analysis['risk_score']:.2f}")
        print(f"Entropie: {analysis['entropy']:.2f}")
        
        if analysis['signature']:
            sig = analysis['signature']
            print(f"Signature: {sig['name']} ({sig['platform']})")
        
        print(f"Opcodes: {len(analysis['opcodes'])}")
    
    def continuous_scan(self, interval=10):
        print(f"Démarrage de l'analyse continue (intervalle: {interval}s)")
        print("Appuyez sur Ctrl+C pour arrêter")
        
        self.running = True
        cycle = 0
        
        try:
            while self.running:
                cycle += 1
                print(f"\n--- Cycle d'Analyse {cycle} ---")
                
                detections = self.scan_all_processes()
                
                if detections:
                    print(f"Trouvé {len(detections)} menaces!")
                else:
                    print("Aucune menace détectée")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nAnalyse continue arrêtée")
            self.running = False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Scanner mémoire pour la détection de shellcode')
    parser.add_argument('--continuous', action='store_true', help='Lancer une analyse continue')
    parser.add_argument('--interval', type=int, default=10, help='Intervalle d\'analyse (secondes)')
    parser.add_argument('--pid', type=int, help='Analyser un processus spécifique')
    
    args = parser.parse_args()
    
    scanner = MemoryScanner()
    
    if not scanner.has_memory_access:
        print("Attention: Aucun accès mémoire disponible")
        return
    
    if args.pid:
        try:
            proc = psutil.Process(args.pid)
            result = scanner.scan_process(proc)
            if result:
                scanner.print_detection(result)
            else:
                print(f"Aucune menace trouvée dans le processus {args.pid}")
        except psutil.NoSuchProcess:
            print(f"Processus {args.pid} introuvable")
    elif args.continuous:
        scanner.continuous_scan(args.interval)
    else:
        scanner.scan_all_processes()


if __name__ == "__main__":
    main() 