# Superbase IMS

Inspection Management System (IMS) using **Streamlit + Supabase**.

## Features
- Dynamic form loading from JSON configs (`form_configs.json`, `forms_mpr_configs.json`)
- Entry, edit, delete, and export records
- File uploads to Supabase storage
- Signature tracking with unsigned row detection

## Files
- `ims_app.py` → Main Streamlit application
- `form_configs.json` → Configs for LW forms
- `forms_mpr_configs.json` → Configs for M&PR forms
- `requirements.txt` → Dependencies list
- `.gitignore` → Keeps secrets and temp files out of repo

## Setup
1. Clone the repo:
   ```bash
   git clone https://github.com/jijolw/superbaseims.git
   cd superbaseims
