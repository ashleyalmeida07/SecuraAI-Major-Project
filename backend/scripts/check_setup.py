"""
Check if Upstash Vector and Neon PostgreSQL are properly configured.
"""

import sys
import os

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings


def check_upstash():
    """Check Upstash Vector connection."""
    print("\n🔍 Checking Upstash Vector...")
    
    if not settings.UPSTASH_SEARCH_REST_URL:
        print("❌ UPSTASH_SEARCH_REST_URL not set in .env")
        return False
    
    if not settings.UPSTASH_SEARCH_REST_TOKEN:
        print("❌ UPSTASH_SEARCH_REST_TOKEN not set in .env")
        return False
    
    print(f"✅ URL configured: {settings.UPSTASH_SEARCH_REST_URL[:50]}...")
    print(f"✅ Token configured: {settings.UPSTASH_SEARCH_REST_TOKEN[:20]}...")
    
    try:
        from upstash_vector import Index
        index = Index(
            url=settings.UPSTASH_SEARCH_REST_URL,
            token=settings.UPSTASH_SEARCH_REST_TOKEN
        )
        
        # Try to get info (will fail if credentials are wrong)
        info = index.info()
        print(f"✅ Connection successful!")
        
        # Handle different response formats
        if hasattr(info, 'dimension'):
            print(f"   Dimension: {info.dimension}")
            print(f"   Metric: {getattr(info, 'similarity_function', 'N/A')}")
            print(f"   Vector count: {getattr(info, 'vector_count', 0)}")
        elif isinstance(info, dict):
            print(f"   Dimension: {info.get('dimension', 'N/A')}")
            print(f"   Metric: {info.get('similarity_function', 'N/A')}")
            print(f"   Vector count: {info.get('vector_count', 0)}")
        else:
            print(f"   Info: {info}")
        
        return True
        
    except ImportError:
        print("⚠️  upstash-vector not installed. Run: pip install upstash-vector")
        return False
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Connection failed: {error_msg}")
        
        # Provide helpful hints
        if "404" in error_msg or "Not Found" in error_msg:
            print("\n💡 Hint: This URL might be for Upstash Search, not Vector")
            print("   Make sure you created a VECTOR index, not a Search index")
            print("   Go to: https://console.upstash.com/vector")
        elif "401" in error_msg or "403" in error_msg or "Unauthorized" in error_msg:
            print("\n💡 Hint: Token might be incorrect or expired")
            print("   Get fresh credentials from: https://console.upstash.com/vector")
        
        return False


def check_postgres():
    """Check PostgreSQL connection."""
    print("\n🔍 Checking Neon PostgreSQL...")
    
    if not settings.POSTGRES_SERVER:
        print("❌ POSTGRES_SERVER not set in .env")
        return False
    
    print(f"✅ Server: {settings.POSTGRES_SERVER}")
    print(f"✅ Database: {settings.POSTGRES_DB}")
    print(f"✅ User: {settings.POSTGRES_USER}")
    
    try:
        from app.db.session import engine
        from app.db.models import Scan, FlowRun, Finding, Fix
        from sqlalchemy import text
        
        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("✅ Connection successful!")
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        required_tables = ["scans", "flow_runs", "findings", "fixes", "users"]
        missing_tables = [t for t in required_tables if t not in tables]
        
        if missing_tables:
            print(f"⚠️  Missing tables: {', '.join(missing_tables)}")
            print("   Run: python scripts/init_db.py")
            return False
        else:
            print(f"✅ All tables present: {', '.join(tables)}")
        
        return True
        
    except ImportError as e:
        print(f"⚠️  Missing dependency: {e}")
        return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False


def check_dependencies():
    """Check required Python packages."""
    print("\n🔍 Checking Python dependencies...")
    
    required = [
        ("upstash-vector", "upstash_vector"),
        ("fastembed", "fastembed"),
        ("sqlalchemy", "sqlalchemy"),
        ("psycopg2", "psycopg2"),
    ]
    
    missing = []
    for package_name, import_name in required:
        try:
            __import__(import_name)
            print(f"✅ {package_name}")
        except ImportError:
            print(f"❌ {package_name}")
            missing.append(package_name)
    
    if missing:
        print(f"\n⚠️  Install missing packages:")
        print(f"   pip install {' '.join(missing)}")
        return False
    
    return True


def main():
    """Run all checks."""
    print("=" * 60)
    print("AuthTrack Database Setup Check")
    print("=" * 60)
    
    deps_ok = check_dependencies()
    upstash_ok = check_upstash()
    postgres_ok = check_postgres()
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Dependencies: {'✅ OK' if deps_ok else '❌ FAILED'}")
    print(f"Upstash Vector: {'✅ OK' if upstash_ok else '❌ FAILED'}")
    print(f"Neon PostgreSQL: {'✅ OK' if postgres_ok else '❌ FAILED'}")
    
    if deps_ok and upstash_ok and postgres_ok:
        print("\n🎉 All checks passed! Ready to seed databases.")
        print("\nNext steps:")
        print("1. Seed Upstash: python scripts/seed_upstash.py")
        print("2. Start backend: uvicorn app.main:app --reload")
    else:
        print("\n⚠️  Some checks failed. Fix issues above before proceeding.")
        print("\nSetup guides:")
        print("- Upstash: https://console.upstash.com/vector")
        print("- Neon: https://console.neon.tech")
        print("- Docs: See VECTOR_DB_SETUP.md")


if __name__ == "__main__":
    main()
