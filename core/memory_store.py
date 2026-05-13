import sqlite3
from datetime import datetime

DB_FILE = "threat_memory.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS memory 
                    (date TEXT, sample TEXT, mitre_ids TEXT, purpose TEXT)''')
        conn.commit()
        conn.close()
    except Exception as e:
        pass

def update_threat_memory(sample_name, mitre_ids, purpose):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        mitre_str = ",".join(list(set(mitre_ids)))
        c.execute("INSERT INTO memory VALUES (?, ?, ?, ?)", 
                (str(datetime.now().date()), sample_name, mitre_str, purpose))
        conn.commit()
        conn.close()
    except Exception: 
        pass

def find_clusters(current_mitre_ids):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT sample, mitre_ids FROM memory")
        records = c.fetchall()
        conn.close()
        
        clusters = []
        current_set = set(current_mitre_ids)
        for record in records[:-1]:
            sample_name, mitre_str = record[0], record[1]
            record_mitre_set = set(mitre_str.split(',')) if mitre_str else set()
            
            shared = current_set.intersection(record_mitre_set)
            if len(shared) > 0:
                match_percentage = int((len(shared) / max(len(current_set), 1)) * 100)
                if match_percentage >= 50:
                    clusters.append({"sample": sample_name, "match": match_percentage, "shared_mitre": list(shared)})
        return sorted(clusters, key=lambda x: x['match'], reverse=True)
    except Exception: 
        return []