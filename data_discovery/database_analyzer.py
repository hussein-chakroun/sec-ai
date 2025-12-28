"""
Database Analyzer
Schema analysis, data discovery, and sensitive information identification in databases
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import sqlite3

@dataclass
class DatabaseSchema:
    """Database schema information"""
    name: str
    tables: List[Dict]
    sensitive_tables: List[str]
    record_counts: Dict[str, int]
    sensitive_columns: List[Dict]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class DatabaseAnalyzer:
    """
    Analyzes database schemas and identifies sensitive data
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        
        # Sensitive table name patterns
        self.sensitive_table_patterns = [
            r'.*user.*', r'.*customer.*', r'.*employee.*',
            r'.*person.*', r'.*account.*', r'.*payment.*',
            r'.*credit.*', r'.*card.*', r'.*medical.*',
            r'.*health.*', r'.*patient.*', r'.*financial.*',
            r'.*transaction.*', r'.*order.*', r'.*invoice.*',
            r'.*salary.*', r'.*payroll.*', r'.*credential.*',
            r'.*password.*', r'.*secret.*', r'.*private.*'
        ]
        
        # Sensitive column name patterns
        self.sensitive_column_patterns = {
            'pii': [
                r'.*ssn.*', r'.*social.*security.*',
                r'.*first.*name.*', r'.*last.*name.*',
                r'.*email.*', r'.*phone.*', r'.*address.*',
                r'.*birth.*', r'.*dob.*', r'.*age.*',
                r'.*gender.*', r'.*passport.*', r'.*license.*'
            ],
            'financial': [
                r'.*card.*number.*', r'.*credit.*card.*',
                r'.*account.*number.*', r'.*routing.*',
                r'.*balance.*', r'.*salary.*', r'.*payment.*',
                r'.*transaction.*', r'.*amount.*'
            ],
            'authentication': [
                r'.*password.*', r'.*passwd.*', r'.*pwd.*',
                r'.*token.*', r'.*secret.*', r'.*key.*',
                r'.*hash.*', r'.*salt.*', r'.*api.*key.*'
            ],
            'medical': [
                r'.*medical.*', r'.*diagnosis.*', r'.*prescription.*',
                r'.*condition.*', r'.*treatment.*', r'.*patient.*'
            ]
        }
        
        self.schemas = []
    
    def analyze_sqlite(self, db_path: str) -> DatabaseSchema:
        """
        Analyze SQLite database
        """
        print(f"[*] Analyzing SQLite database: {db_path}")
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            schema_info = {
                'name': db_path,
                'tables': [],
                'sensitive_tables': [],
                'record_counts': {},
                'sensitive_columns': []
            }
            
            for table in tables:
                # Get table schema
                cursor.execute(f"PRAGMA table_info({table});")
                columns = cursor.fetchall()
                
                table_info = {
                    'name': table,
                    'columns': []
                }
                
                for col in columns:
                    col_info = {
                        'name': col[1],
                        'type': col[2],
                        'nullable': not col[3],
                        'primary_key': bool(col[5])
                    }
                    table_info['columns'].append(col_info)
                    
                    # Check if column is sensitive
                    sensitivity = self._check_column_sensitivity(col[1])
                    if sensitivity:
                        schema_info['sensitive_columns'].append({
                            'table': table,
                            'column': col[1],
                            'type': sensitivity,
                            'data_type': col[2]
                        })
                
                schema_info['tables'].append(table_info)
                
                # Get record count
                cursor.execute(f"SELECT COUNT(*) FROM {table};")
                count = cursor.fetchone()[0]
                schema_info['record_counts'][table] = count
                
                # Check if table is sensitive
                if self._is_sensitive_table(table):
                    schema_info['sensitive_tables'].append(table)
            
            conn.close()
            
            schema = DatabaseSchema(**schema_info)
            self.schemas.append(schema)
            
            self._print_schema_summary(schema)
            
            return schema
            
        except Exception as e:
            print(f"[!] Error analyzing database: {str(e)}")
            return None
    
    def analyze_mysql_schema(self, connection_params: Dict) -> DatabaseSchema:
        """
        Analyze MySQL database schema
        """
        try:
            import pymysql
            
            conn = pymysql.connect(**connection_params)
            cursor = conn.cursor()
            
            # Get database name
            cursor.execute("SELECT DATABASE();")
            db_name = cursor.fetchone()[0]
            
            # Get all tables
            cursor.execute("SHOW TABLES;")
            tables = [row[0] for row in cursor.fetchall()]
            
            schema_info = {
                'name': db_name,
                'tables': [],
                'sensitive_tables': [],
                'record_counts': {},
                'sensitive_columns': []
            }
            
            for table in tables:
                # Get table schema
                cursor.execute(f"DESCRIBE {table};")
                columns = cursor.fetchall()
                
                table_info = {
                    'name': table,
                    'columns': []
                }
                
                for col in columns:
                    col_info = {
                        'name': col[0],
                        'type': col[1],
                        'nullable': col[2] == 'YES',
                        'primary_key': col[3] == 'PRI'
                    }
                    table_info['columns'].append(col_info)
                    
                    # Check sensitivity
                    sensitivity = self._check_column_sensitivity(col[0])
                    if sensitivity:
                        schema_info['sensitive_columns'].append({
                            'table': table,
                            'column': col[0],
                            'type': sensitivity,
                            'data_type': col[1]
                        })
                
                schema_info['tables'].append(table_info)
                
                # Get record count
                cursor.execute(f"SELECT COUNT(*) FROM {table};")
                count = cursor.fetchone()[0]
                schema_info['record_counts'][table] = count
                
                if self._is_sensitive_table(table):
                    schema_info['sensitive_tables'].append(table)
            
            conn.close()
            
            schema = DatabaseSchema(**schema_info)
            self.schemas.append(schema)
            
            return schema
            
        except Exception as e:
            print(f"[!] Error analyzing MySQL database: {str(e)}")
            return None
    
    def analyze_postgresql_schema(self, connection_params: Dict) -> DatabaseSchema:
        """
        Analyze PostgreSQL database schema
        """
        try:
            import psycopg2
            
            conn = psycopg2.connect(**connection_params)
            cursor = conn.cursor()
            
            # Get database name
            cursor.execute("SELECT current_database();")
            db_name = cursor.fetchone()[0]
            
            # Get all tables
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            schema_info = {
                'name': db_name,
                'tables': [],
                'sensitive_tables': [],
                'record_counts': {},
                'sensitive_columns': []
            }
            
            for table in tables:
                # Get table schema
                cursor.execute(f"""
                    SELECT column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_name = '{table}'
                """)
                columns = cursor.fetchall()
                
                table_info = {
                    'name': table,
                    'columns': []
                }
                
                for col in columns:
                    col_info = {
                        'name': col[0],
                        'type': col[1],
                        'nullable': col[2] == 'YES'
                    }
                    table_info['columns'].append(col_info)
                    
                    sensitivity = self._check_column_sensitivity(col[0])
                    if sensitivity:
                        schema_info['sensitive_columns'].append({
                            'table': table,
                            'column': col[0],
                            'type': sensitivity,
                            'data_type': col[1]
                        })
                
                schema_info['tables'].append(table_info)
                
                # Get record count
                cursor.execute(f"SELECT COUNT(*) FROM {table};")
                count = cursor.fetchone()[0]
                schema_info['record_counts'][table] = count
                
                if self._is_sensitive_table(table):
                    schema_info['sensitive_tables'].append(table)
            
            conn.close()
            
            schema = DatabaseSchema(**schema_info)
            self.schemas.append(schema)
            
            return schema
            
        except Exception as e:
            print(f"[!] Error analyzing PostgreSQL database: {str(e)}")
            return None
    
    def _is_sensitive_table(self, table_name: str) -> bool:
        """Check if table name suggests sensitive data"""
        table_lower = table_name.lower()
        
        for pattern in self.sensitive_table_patterns:
            if re.match(pattern, table_lower):
                return True
        
        return False
    
    def _check_column_sensitivity(self, column_name: str) -> Optional[str]:
        """Check if column name suggests sensitive data"""
        column_lower = column_name.lower()
        
        for category, patterns in self.sensitive_column_patterns.items():
            for pattern in patterns:
                if re.match(pattern, column_lower):
                    return category
        
        return None
    
    def _print_schema_summary(self, schema: DatabaseSchema):
        """Print summary of database schema analysis"""
        print(f"\n[+] Database Analysis Complete: {schema.name}")
        print(f"    Total Tables: {len(schema.tables)}")
        print(f"    Sensitive Tables: {len(schema.sensitive_tables)}")
        print(f"    Sensitive Columns: {len(schema.sensitive_columns)}")
        print(f"    Total Records: {sum(schema.record_counts.values())}")
        
        if schema.sensitive_tables:
            print(f"\n[!] Sensitive Tables:")
            for table in schema.sensitive_tables[:5]:
                count = schema.record_counts.get(table, 0)
                print(f"    - {table} ({count} records)")
    
    def estimate_exfiltration_impact(self, schema: DatabaseSchema) -> Dict:
        """
        Estimate the impact of exfiltrating database data
        """
        impact = {
            'total_records': sum(schema.record_counts.values()),
            'sensitive_records': 0,
            'pii_exposure': 0,
            'financial_exposure': 0,
            'estimated_size_mb': 0,
            'risk_level': 'low'
        }
        
        # Calculate sensitive records
        for table in schema.sensitive_tables:
            impact['sensitive_records'] += schema.record_counts.get(table, 0)
        
        # Categorize by type
        for col_info in schema.sensitive_columns:
            count = schema.record_counts.get(col_info['table'], 0)
            
            if col_info['type'] == 'pii':
                impact['pii_exposure'] += count
            elif col_info['type'] == 'financial':
                impact['financial_exposure'] += count
        
        # Estimate size (rough)
        impact['estimated_size_mb'] = (impact['total_records'] * 500) / (1024 * 1024)  # ~500 bytes/record
        
        # Determine risk level
        if impact['pii_exposure'] > 10000 or impact['financial_exposure'] > 1000:
            impact['risk_level'] = 'critical'
        elif impact['pii_exposure'] > 1000 or impact['financial_exposure'] > 100:
            impact['risk_level'] = 'high'
        elif impact['sensitive_records'] > 100:
            impact['risk_level'] = 'medium'
        
        return impact
    
    def generate_report(self) -> Dict:
        """Generate comprehensive database analysis report"""
        report = {
            'total_databases': len(self.schemas),
            'databases': []
        }
        
        for schema in self.schemas:
            db_report = schema.to_dict()
            db_report['impact_assessment'] = self.estimate_exfiltration_impact(schema)
            report['databases'].append(db_report)
        
        return report
    
    def export_results(self, output_file: str):
        """Export analysis results"""
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Database analysis exported to: {output_file}")
