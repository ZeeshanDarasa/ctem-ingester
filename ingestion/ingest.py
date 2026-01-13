#!/usr/bin/env python3
"""
Simple ingestion script for processing scan files.
Can be called directly by n8n workflows.

Database tables are automatically created if they don't exist (auto-initialization).

Usage:
    python ingest.py /path/to/scan.xml --office-id=office-1 --scanner-id=scanner-1
    python ingest.py /path/to/scan.xml --office-id=office-1 --scanner-id=scanner-1 --json
    python ingest.py /path/to/nuclei.json --office-id=office-1 --scanner-id=scanner-1 --scanner-type=nuclei
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.transformers.registry import get_transformer
from src.storage.database import get_db_session, init_database
from src.storage.repository import ingest_events


def main():
    parser = argparse.ArgumentParser(description='Process scan files and ingest exposures')
    parser.add_argument('file_path', help='Path to scan file')
    parser.add_argument('--office-id', required=True, help='Office identifier')
    parser.add_argument('--scanner-id', required=True, help='Scanner identifier')
    parser.add_argument('--scanner-type', default='nmap', help='Scanner type (default: nmap)')
    parser.add_argument('--json', action='store_true', help='Output JSON format')
    parser.add_argument('--init-db', action='store_true', help='Force database initialization (optional, auto-detects by default)')
    
    args = parser.parse_args()
    
    try:
        # Force initialize database if explicitly requested (optional - auto-init happens anyway)
        if args.init_db:
            init_database()
            if not args.json:
                print("✓ Database initialized")
        
        # Validate file exists
        file_path = Path(args.file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {args.file_path}")
        
        # Get transformer
        transformer = get_transformer(args.scanner_type)
        if not transformer:
            raise ValueError(f"Unsupported scanner type: {args.scanner_type}")
        
        # Transform file to events
        start_time = datetime.now()
        events = transformer.transform(
            file_path=file_path,
            office_id=args.office_id,
            scanner_id=args.scanner_id
        )
        
        # Ingest to database
        with get_db_session() as session:
            stats = ingest_events(session, events)
        
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Output results
        result = {
            'status': 'success',
            'file': str(file_path),
            'events': stats['events_inserted'],
            'exposures_new': stats['exposures_inserted'],
            'exposures_updated': stats['exposures_updated'],
            'processing_ms': int(processing_time)
        }
        
        if args.json:
            print(json.dumps(result))
        else:
            print(f"✓ Processed {file_path.name}")
            print(f"  Events: {stats['events_inserted']}")
            print(f"  New exposures: {stats['exposures_inserted']}")
            print(f"  Updated exposures: {stats['exposures_updated']}")
            print(f"  Time: {int(processing_time)}ms")
        
        sys.exit(0)
        
    except Exception as e:
        error_result = {
            'status': 'error',
            'error': str(e),
            'file': args.file_path
        }
        
        if args.json:
            print(json.dumps(error_result))
        else:
            print(f"✗ Error: {e}", file=sys.stderr)
        
        sys.exit(1)


if __name__ == '__main__':
    main()
