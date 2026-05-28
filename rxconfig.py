"""
Aegis-Antigravity SRE: Reflex Compiler Configuration
-----------------------------------------------------
This configuration file instructs the Reflex compiler engine how to bootstrap
and bundle the project application workspace.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Single Application Namespace:
   We configure `app_name="aegis_app"` to map directly to our project source package.
   Reflex compiles python classes inside aegis_app/aegis_app.py into modular React pages 
   and standard Next.js components served by an underlying FastAPI backend.
   
2. Next.js Asset Isolation:
   The compiled frontend bundle is placed under a hidden `.web/` directory during compilation, 
   separating the compiled assets from our core python agent scripts and local parquet logs.
"""

import reflex as rx

config = rx.Config(
    app_name="aegis_app",
    disable_plugins=["SitemapPlugin"],
)
