#!/usr/bin/env python
import os
import sys
import subprocess

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 60)
    print("Starting OSINT Vision Pro FastAPI Server")
    print("=" * 60)
    
    # Ensure dependencies are available
    try:
        import uvicorn
        import fastapi
    except ImportError:
        print("Installing required Python packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    print("\nDashboard will be available at: http://localhost:8000")
    print("API Docs available at:           http://localhost:8000/docs\n")
    
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()

