# Enhanced IMS — Role-Based Signature System with Simplified Delete & RBAC
import os
import io
import json
import urllib.parse
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import pandas as pd
import streamlit as st
from supabase import create_client, Client
import plotly.express as px
import plotly.graph_objects as go

# --------------------------
# Streamlit / Supabase setup
# --------------------------
st.set_page_config(page_title="IMS Enhanced", page_icon="🗂️", layout="wide")

SUPABASE_URL = st.secrets["supabase"]["url"]
SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
BUCKET = st.secrets.get("supabase", {}).get("bucket", "ims-uploads")

sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
MAX_FILE_SIZE_MB = 50

# Use the new enhanced table
TABLE_NAME = "ims_entries_enhanced"

# --------------------------
# Role-based Access Control
# --------------------------
def get_user_permissions(user_roles: List[str], user_config: Dict, form_code: str = None, form_config: Dict = None) -> Dict[str, bool]:
    """Get combined permissions for user based on all their roles and specific form"""
    authority_matrix = user_config.get("authority_matrix", {})
    
    permissions = {
        "can_create": False,  # Now restricted based on form
        "can_edit": False,
        "can_delete": False,
        "can_view": True,    # Everyone can view
        "can_sign": True,    # Everyone can sign (if they have authority)
        "can_override": False
    }
    
    # Check form-specific creation permission
    if form_code and form_config:
        permissions["can_create"] = can_user_create_form(user_roles, form_code, form_config, user_config)
    else:
        # General permission check - if they can create any form
        admin_roles = authority_matrix.get("can_edit_any", [])
        permissions["can_create"] = any(role in user_roles for role in admin_roles) or "JE" in user_roles
    
    # Check other permissions (existing logic)
    for perm_type, allowed_roles in authority_matrix.items():
        if perm_type.startswith("can_") and any(role in user_roles for role in allowed_roles):
            perm_key = perm_type
            if perm_key == "can_edit_any" or perm_key == "can_edit_lower_hierarchy" or perm_key == "can_edit_own_only":
                permissions["can_edit"] = True
            elif perm_key == "can_delete_any" or perm_key == "can_delete_with_confirmation" or perm_key == "can_delete_own_draft_only":
                permissions["can_delete"] = True
            elif perm_key == "can_override":
                permissions["can_override"] = True
    
    return permissions

def can_user_create_form(user_roles: List[str], form_code: str, form_config: Dict, user_config: Dict) -> bool:
    """Check if user can create entries for a specific form"""
    authority_matrix = user_config.get("authority_matrix", {})
    
    # Admin/SSE/IMS can always create any form
    admin_roles = authority_matrix.get("can_edit_any", [])
    if any(role in user_roles for role in admin_roles):
        return True
    
    # JE can always initiate forms (they are the starting point)
    if "JE" in user_roles:
        return True
    
    # Check if user has any signing authority for this specific form
    signatures_config = form_config.get("signatures", {})
    
    for sig_name, sig_config in signatures_config.items():
        required_roles = sig_config.get("roles", [])
        if any(role in user_roles for role in required_roles):
            return True
    
    return False

def can_user_edit_record(user_info: Dict, record: Dict, user_config: Dict) -> bool:
    """Check if user can edit a specific record"""
    authority_matrix = user_config.get("authority_matrix", {})
    user_roles = user_info["roles"]
    
    # Admin can edit anything
    if any(role in authority_matrix.get("can_edit_any", []) for role in user_roles):
        return True
    
    # Check if form is completed - only admins can edit completed forms
    form_status = record.get("form_status", "draft")
    if form_status == "complete":
        return any(role in authority_matrix.get("can_edit_any", []) for role in user_roles)
    
    # Users can edit their own records if they have any edit permission
    created_by_email = record.get("created_by_email", "")
    if created_by_email == user_info["email"]:
        edit_own = authority_matrix.get("can_edit_own_only", [])
        edit_lower = authority_matrix.get("can_edit_lower_hierarchy", [])
        edit_any = authority_matrix.get("can_edit_any", [])
        if any(role in user_roles for role in edit_own + edit_lower + edit_any):
            return True
    
    # Higher authority can edit lower authority records
    if any(role in authority_matrix.get("can_edit_lower_hierarchy", []) for role in user_roles):
        return True
    
    return False

def can_user_delete_record(user_info: Dict, record: Dict, user_config: Dict) -> bool:
    """Check if user can delete a specific record"""
    authority_matrix = user_config.get("authority_matrix", {})
    user_roles = user_info["roles"]
    
    # Admin can delete anything
    if any(role in authority_matrix.get("can_delete_any", []) for role in user_roles):
        return True
    
    form_status = record.get("form_status", "draft")
    
    # Users can delete their own draft records
    created_by_email = record.get("created_by_email", "")
    if (created_by_email == user_info["email"] and 
        form_status == "draft" and 
        any(role in authority_matrix.get("can_delete_own_draft_only", []) for role in user_roles)):
        return True
    
    # Higher authority can delete with confirmation
    if any(role in authority_matrix.get("can_delete_with_confirmation", []) for role in user_roles):
        # Can't delete completed forms unless admin
        if form_status == "complete":
            return any(role in authority_matrix.get("can_delete_any", []) for role in user_roles)
        return True
    
    return False

def delete_record_with_files(record_id: str, file_metadata: List[Dict]) -> bool:
    """Delete a single record and its associated files"""
    try:
        # Delete files from storage first
        if file_metadata:
            file_paths = [f.get("storage_path") for f in file_metadata if f.get("storage_path")]
            if file_paths:
                for path in file_paths:
                    try:
                        sb.storage.from_(BUCKET).remove([path])
                    except Exception as e:
                        st.warning(f"Could not delete file {path}: {e}")
        
        # Delete record from database
        result = sb.table(TABLE_NAME).delete().eq("id", record_id).execute()
        
        # Check if deletion was successful
        if hasattr(result, 'data') and result.data is not None:
            return True
        else:
            # Alternative check - try to fetch the record to see if it still exists
            check_result = sb.table(TABLE_NAME).select("id").eq("id", record_id).execute()
            return len(check_result.data) == 0
    
    except Exception as e:
        st.error(f"Error deleting record: {e}")
        return False

def get_user_creatable_forms(user_roles: List[str], user_config: Dict) -> Dict[str, List[str]]:
    """Get list of forms user can create, organized by group"""
    authority_matrix = user_config.get("authority_matrix", {})
    
    # Load form configurations
    forms_lw = load_json("form_configs_enhanced.json")
    forms_mpr = load_json("forms_mpr_configs_enhanced.json")
    
    creatable_forms = {
        "LW FILES": [],
        "M&PR FILES": []
    }
    
    # Check LW forms
    for form_code, form_config in forms_lw.items():
        if can_user_create_form(user_roles, form_code, form_config, user_config):
            creatable_forms["LW FILES"].append(form_code)
    
    # Check MPR forms  
    for form_code, form_config in forms_mpr.items():
        if can_user_create_form(user_roles, form_code, form_config, user_config):
            creatable_forms["M&PR FILES"].append(form_code)
    
    return creatable_forms

def show_permission_explanation(user_roles: List[str], form_code: str, form_config: Dict):
    """Show why user can create this form"""
    signatures_config = form_config.get("signatures", {})
    
    reasons = []
    
    if "JE" in user_roles:
        reasons.append("You are a Junior Engineer (JE) - can initiate all forms")
    
    for sig_name, sig_config in signatures_config.items():
        required_roles = sig_config.get("roles", [])
        if any(role in user_roles for role in required_roles):
            reasons.append(f"You have signing authority for: {sig_name}")
    
    if reasons:
        st.info("**Reason:** " + " | ".join(reasons))

# --------------------------
# Authentication System (Enhanced)
# --------------------------
@st.cache_data
def load_user_config():
    """Load user roles configuration"""
    try:
        with open("user_roles.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": {}, "role_descriptions": {}, "authority_matrix": {}, "passwords": {}}

def hash_password(password: str) -> str:
    """Hash a password for storing"""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate user and return user info"""
    user_config = load_user_config()
    users = user_config.get("users", {})
    passwords = user_config.get("passwords", {})
    
    if username not in users:
        return None
    
    user = users[username]
    
    # For demo purposes, check against the plain password from config
    if username in passwords and password == passwords[username]:
        return {
            "username": username,
            "name": user["name"],
            "roles": user["roles"],
            "email": user["email"],
            "department": user.get("department", "Unknown")
        }
    
    # Fallback: check against stored hash
    if hash_password(password) == user.get("password_hash"):
        return {
            "username": username,
            "name": user["name"],
            "roles": user["roles"],
            "email": user["email"],
            "department": user.get("department", "Unknown")
        }
    return None

def require_login() -> Dict:
    """Show login form if user not authenticated"""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        st.title("🔐 IMS Enhanced Login")
        st.markdown("**Demo Credentials:**")
        user_config = load_user_config()
        passwords = user_config.get("passwords", {})
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Available Users:**")
            for user, pwd in passwords.items():
                if user != "comment":
                    st.code(f"{user} / {pwd}")
        
        with col2:
            st.markdown("**Available Roles:**")
            role_desc = user_config.get("role_descriptions", {})
            for role, desc in role_desc.items():
                st.caption(f"**{role}:** {desc}")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login", type="primary")
            
            if submit:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user_info = user
                    st.success(f"Welcome, {user['name']}!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
        st.stop()
    
    return st.session_state.user_info

def logout():
    """Logout current user"""
    st.session_state.authenticated = False
    if "user_info" in st.session_state:
        del st.session_state.user_info
    st.rerun()

# --------------------------
# Enhanced Signature System
# --------------------------
def get_signature_status_display(signatures: Dict, signature_name: str) -> str:
    """Get display text for signature status"""
    sig_data = signatures.get(signature_name, {})
    if isinstance(sig_data, dict) and sig_data.get("signed", False):
        signed_by = sig_data.get("signed_by_name", "Unknown")
        department = sig_data.get("department", "")
        signed_at = sig_data.get("signed_at", "")[:10]
        return f"✅ {signed_by} ({department}) - {signed_at}"
    return "❌ Pending"

def get_form_signature_progress(signatures: Dict, form_config: Dict) -> Dict[str, Any]:
    """Calculate signature progress for a form"""
    signatures_config = form_config.get("signatures", {})
    total_signatures = len(signatures_config)
    
    if total_signatures == 0:
        return {"completed": 0, "total": 0, "progress": 100, "status": "complete"}
    
    completed = 0
    for sig_name in signatures_config.keys():
        sig_data = signatures.get(sig_name, {})
        if isinstance(sig_data, dict) and sig_data.get("signed", False):
            completed += 1
    
    progress = (completed / total_signatures) * 100 if total_signatures else 100
    
    if completed == 0:
        status = "draft"
    elif completed == total_signatures:
        status = "complete"
    else:
        status = "in_progress"
    
    return {
        "completed": completed,
        "total": total_signatures,
        "progress": progress,
        "status": status
    }

def get_visible_signatures(form_code: str, user_roles: List[str], form_config: Dict) -> List[str]:
    """Get signatures visible to current user role"""
    signatures_config = form_config.get("signatures", {})
    visible_sigs = []
    
    for sig_name, sig_config in signatures_config.items():
        required_roles = sig_config.get("roles", [])
        if any(role in user_roles for role in required_roles):
            visible_sigs.append(sig_name)
    
    return visible_sigs

def can_user_sign(form_code: str, signature_name: str, user_roles: List[str], 
                  current_signatures: Dict, form_config: Dict) -> bool:
    """Check if user can sign based on workflow rules"""
    signatures_config = form_config.get("signatures", {})
    sig_config = signatures_config.get(signature_name, {})
    
    if not sig_config:
        return False
    
    # Check if user has required role
    required_roles = sig_config.get("roles", [])
    if not any(role in user_roles for role in required_roles):
        return False
    
    # Check if signature is already completed
    current_sig = current_signatures.get(signature_name, {})
    if isinstance(current_sig, dict) and current_sig.get("signed", False):
        return False
    elif isinstance(current_sig, bool) and current_sig:
        return False
    
    # Check dependencies
    depends_on = sig_config.get("depends_on", [])
    for dep_sig in depends_on:
        dep_status = current_signatures.get(dep_sig, {})
        if isinstance(dep_status, dict):
            if not dep_status.get("signed", False):
                return False
        elif isinstance(dep_status, bool):
            if not dep_status:
                return False
        else:
            return False
    
    return True

def create_signature_entry(user_info: Dict, timestamp: Optional[str] = None, comment: str = "") -> Dict:
    """Create a signature entry with metadata"""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    
    return {
        "signed": True,
        "signed_by": user_info["email"],
        "signed_by_name": user_info["name"],
        "signed_by_roles": user_info["roles"],
        "signed_at": timestamp,
        "department": user_info.get("department", "Unknown"),
        "comment": comment
    }

def render_signature_section(form_code: str, user_info: Dict, form_config: Dict, 
                           current_signatures: Optional[Dict] = None) -> Dict:
    """Render signature section based on user role"""
    if current_signatures is None:
        current_signatures = {}
    
    user_roles = user_info["roles"]
    signatures_config = form_config.get("signatures", {})
    
    if not signatures_config:
        st.warning("⚠️ No signatures configured for this form type")
        return {}
    
    st.markdown("### 📝 **Signature Section**")
    sig_values = {}
    
    # Sort signatures by order
    sorted_sigs = sorted(signatures_config.items(), key=lambda x: x[1].get("order", 999))
    
    for sig_name, sig_config in sorted_sigs:
        current_status = current_signatures.get(sig_name, {})
        required_roles = sig_config.get("roles", [])
        
        # Check if user should see this signature
        user_can_see = any(role in user_roles for role in required_roles)
        
        if isinstance(current_status, dict) and current_status.get("signed", False):
            # Signature already completed - show status if user can see it
            if user_can_see:
                signed_by = current_status.get("signed_by_name", "Unknown")
                signed_at = current_status.get("signed_at", "Unknown")[:16]
                department = current_status.get("department", "")
                comment = current_status.get("comment", "")
                
                st.success(f"✅ **{sig_name}**")
                st.caption(f"Signed by: {signed_by} ({department}) on {signed_at}")
                if comment:
                    st.caption(f"Comment: {comment}")
                    
            sig_values[sig_name] = current_status
            
        elif user_can_see:
            # User can potentially sign this
            can_sign = can_user_sign(form_code, sig_name, user_roles, current_signatures, form_config)
            
            if can_sign:
                description = sig_config.get("description", "")
                help_text = f"{description} (Required roles: {', '.join(required_roles)})"
                
                col1, col2 = st.columns([3, 1])
                with col1:
                    sig_values[sig_name] = st.checkbox(
                        f"✏️ **{sig_name}**", 
                        value=False, 
                        help=help_text,
                        key=f"sig_{sig_name}"
                    )
                with col2:
                    if sig_values.get(sig_name, False):
                        sig_values[f"{sig_name}_comment"] = st.text_input(
                            "Comment (optional)", 
                            key=f"comment_{sig_name}",
                            placeholder="Add signature comment..."
                        )
            else:
                depends_on = sig_config.get("depends_on", [])
                if depends_on:
                    pending_deps = [dep for dep in depends_on 
                                  if not current_signatures.get(dep, {}).get("signed", False)]
                    if pending_deps:
                        st.warning(f"⏳ **{sig_name}** - Waiting for: {', '.join(pending_deps)}")
                else:
                    st.info(f"ℹ️ **{sig_name}** - Pending")
                sig_values[sig_name] = False
        else:
            # User cannot see this signature - don't show it
            sig_values[sig_name] = current_status if current_status else False
    
    return sig_values

# --------------------------
# Edit functionality
# --------------------------
def render_edit_form(record: Dict, form_config: Dict, user_info: Dict):
    """Render form for editing an existing record"""
    st.subheader(f"✏️ Edit Record - {record.get('form_code', 'Unknown')}")
    
    # Show record info
    col1, col2, col3 = st.columns(3)
    with col1:
        st.caption(f"**Created by:** {record.get('created_by', 'Unknown')}")
    with col2:
        st.caption(f"**Created on:** {record.get('created_at', '')[:16]}")
    with col3:
        st.caption(f"**Status:** {record.get('form_status', 'draft').title()}")
    
    # Warning about signature reset
    if record.get("signatures"):
        st.warning("⚠️ **Important:** Editing this form will reset all signatures. All signatories will need to sign again.")
    
    with st.form(f"edit_form_{record['id']}"):
        fields = form_config.get("fields", [])
        current_data = record.get("data", {})
        
        st.markdown("### 📋 Form Data")
        values = {}
        
        # Arrange fields in columns
        num_cols = 2
        cols = st.columns(num_cols)
        for i, fld in enumerate(fields):
            with cols[i % num_cols]:
                current_value = current_data.get(fld, "")
                is_long = any(k in fld.lower() for k in ["remarks", "details", "description", "action", "cause"])
                if is_long:
                    values[fld] = st.text_area(fld, value=current_value, height=100)
                else:
                    values[fld] = st.text_input(fld, value=current_value)
        
        st.markdown("---")
        
        # Priority selection
        current_priority = record.get("priority", "normal")
        priority = st.selectbox("Priority", ["normal", "high", "urgent"], 
                              index=["normal", "high", "urgent"].index(current_priority))
        
        # File management
        st.markdown("### 📎 File Management")
        current_files = record.get("file_metadata", [])
        
        if current_files:
            st.markdown("**Current Files:**")
            files_to_keep = []
            for i, file_meta in enumerate(current_files):
                col1, col2 = st.columns([3, 1])
                with col1:
                    keep_file = st.checkbox(
                        f"📄 {file_meta['original_name']} ({file_meta.get('file_size', 0):,} bytes)",
                        value=True,
                        key=f"keep_file_{i}"
                    )
                    if keep_file:
                        files_to_keep.append(file_meta)
                with col2:
                    url = get_file_download_url(file_meta['storage_path'], file_meta['original_name'])
                    st.markdown(f"[📥 Download]({url})")
        else:
            files_to_keep = []
        
        # New file uploads
        st.markdown("**Add New Files:**")
        new_uploads = st.file_uploader(
            "Upload additional files", 
            type=None, 
            accept_multiple_files=True,
            key=f"edit_file_uploader_{record['id']}"
        )
        
        col1, col2 = st.columns(2)
        with col1:
            submitted = st.form_submit_button("💾 Save Changes", type="primary")
        with col2:
            cancel = st.form_submit_button("❌ Cancel", type="secondary")
    
    if cancel:
        st.session_state.editing_record = None
        st.rerun()
    
    if submitted:
        # Validate required fields
        missing_fields = [f for f in fields if not values.get(f, "").strip()]
        if missing_fields:
            st.error(f"Please fill in required fields: {', '.join(missing_fields)}")
        else:
            # Handle file operations
            files_to_delete = []
            if current_files:
                current_paths = [f['storage_path'] for f in current_files]
                kept_paths = [f['storage_path'] for f in files_to_keep]
                files_to_delete = [path for path in current_paths if path not in kept_paths]
            
            # Upload new files
            new_paths, new_metadata = upload_files(record['form_code'], new_uploads) if new_uploads else ([], [])
            
            # Combine file metadata
            final_file_metadata = files_to_keep + new_metadata
            final_file_urls = [f['storage_path'] for f in final_file_metadata]
            
            # Reset signatures due to edit
            reset_signatures = {}
            
            # Update record
            update_payload = {
                "data": values,
                "signatures": reset_signatures,  # Clear all signatures
                "signature_comments": {},  # Clear signature comments
                "file_urls": final_file_urls,
                "file_metadata": final_file_metadata,
                "priority": priority,
                "form_status": "draft",  # Reset to draft since signatures are cleared
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": user_info["name"],
                "updated_by_email": user_info["email"]
            }
            
            try:
                # Update database
                sb.table(TABLE_NAME).update(update_payload).eq("id", record["id"]).execute()
                
                # Delete old files that are no longer needed
                if files_to_delete:
                    for path in files_to_delete:
                        try:
                            sb.storage.from_(BUCKET).remove([path])
                        except Exception as e:
                            st.warning(f"Could not delete file {path}: {e}")
                
                st.success("✅ Record updated successfully! All signatures have been reset.")
                st.info("📋 This form will need to go through the signature process again.")
                
                # Clear editing state
                st.session_state.editing_record = None
                st.rerun()
                
            except Exception as e:
                st.error(f"Error updating record: {e}")

# --------------------------
# File handling
# --------------------------
def validate_uploaded_file(file) -> bool:
    if not file: return False
    size = len(file.getvalue())
    if size > MAX_FILE_SIZE_MB * 1024 * 1024:
        st.error(f"File too large: {size/1024/1024:.1f}MB (max {MAX_FILE_SIZE_MB}MB)")
        return False
    return True

def upload_files(form_code: str, files) -> tuple[List[str], List[Dict[str, Any]]]:
    paths, metadata = [], []
    folder = form_code.replace(" ", "_")
    for f in files or []:
        if not validate_uploaded_file(f): continue
        uid = str(uuid4())[:8]
        safe_name = f"{uid}_{f.name}"
        obj = f"{folder}/{safe_name}"
        data = f.getvalue()
        sb.storage.from_(BUCKET).upload(obj, data)
        paths.append(obj)
        metadata.append({
            "storage_path": obj,
            "original_name": f.name,
            "file_size": len(data),
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
        })
        st.success(f"Uploaded: {f.name}")
    return paths, metadata

def get_file_download_url(path: str, name: str) -> str:
    try:
        encoded_path = urllib.parse.quote(path, safe='/')
        public_url = sb.storage.from_(BUCKET).get_public_url(encoded_path)
        encoded_name = urllib.parse.quote(name)
        if "?" in public_url:
            final_url = f"{public_url}&download={encoded_name}"
        else:
            final_url = f"{public_url}?download={encoded_name}"
        return final_url
    except Exception:
        encoded_path = urllib.parse.quote(path, safe='/')
        encoded_name = urllib.parse.quote(name)
        fallback_url = f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET}/{encoded_path}?download={encoded_name}"
        return fallback_url

# --------------------------
# Load enhanced form configs
# --------------------------
@st.cache_data
def load_json(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# --------------------------
# Dashboard Functions
# --------------------------
def get_all_system_data():
    """Fetch all records from the system"""
    try:
        result = sb.table(TABLE_NAME).select("*").order("created_at", desc=True).execute()
        return result.data or []
    except Exception as e:
        st.error(f"Error fetching system data: {e}")
        return []

def create_priority_chart(data):
    """Create priority distribution chart"""
    if not data:
        return None
    
    # Count priorities
    priority_counts = {}
    for record in data:
        priority = record.get("priority", "normal")
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    
    # Create bar chart
    priorities = list(priority_counts.keys())
    counts = list(priority_counts.values())
    colors = {'normal': '#3498db', 'high': '#f39c12', 'urgent': '#e74c3c'}
    
    fig = go.Figure(data=[
        go.Bar(
            x=priorities,
            y=counts,
            marker_color=[colors.get(p, '#95a5a6') for p in priorities],
            text=counts,
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Priority Distribution",
        xaxis_title="Priority Level",
        yaxis_title="Number of Records",
        height=400,
        showlegend=False
    )
    
    return fig

def create_status_chart(data):
    """Create status distribution pie chart"""
    if not data:
        return None
    
    status_counts = {}
    for record in data:
        status = record.get("form_status", "draft")
        status_counts[status] = status_counts.get(status, 0) + 1
    
    fig = go.Figure(data=[go.Pie(
        labels=list(status_counts.keys()),
        values=list(status_counts.values()),
        hole=.3,
        marker_colors=['#e74c3c', '#f39c12', '#2ecc71']
    )])
    
    fig.update_layout(
        title="Form Status Distribution",
        height=400
    )
    
    return fig

def create_form_type_chart(data):
    """Create form type distribution chart"""
    if not data:
        return None
    
    form_counts = {}
    for record in data:
        form_code = record.get("form_code", "Unknown")
        form_counts[form_code] = form_counts.get(form_code, 0) + 1
    
    # Sort by count for better visualization
    sorted_forms = sorted(form_counts.items(), key=lambda x: x[1], reverse=True)
    forms = [x[0] for x in sorted_forms]
    counts = [x[1] for x in sorted_forms]
    
    fig = go.Figure(data=[
        go.Bar(
            x=counts,
            y=forms,
            orientation='h',
            marker_color='#3498db',
            text=counts,
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Records by Form Type",
        xaxis_title="Number of Records",
        yaxis_title="Form Code",
        height=max(400, len(forms) * 30),
        showlegend=False
    )
    
    return fig

def create_department_chart(data):
    """Create department distribution chart"""
    if not data:
        return None
    
    dept_counts = {}
    for record in data:
        dept = record.get("created_by_department", "Unknown")
        dept_counts[dept] = dept_counts.get(dept, 0) + 1
    
    fig = go.Figure(data=[go.Pie(
        labels=list(dept_counts.keys()),
        values=list(dept_counts.values()),
        hole=.3
    )])
    
    fig.update_layout(
        title="Records by Department",
        height=400
    )
    
    return fig

def create_daily_activity_chart(data):
    """Create daily activity chart for the last 30 days"""
    if not data:
        return None
    
    from datetime import timedelta
    
    # Get dates from last 30 days
    today = datetime.now(timezone.utc).date()
    dates = [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
    
    daily_counts = {date: 0 for date in dates}
    
    for record in data:
        created_date = record.get("created_at", "")[:10]
        if created_date in daily_counts:
            daily_counts[created_date] += 1
    
    fig = go.Figure(data=[
        go.Scatter(
            x=list(daily_counts.keys()),
            y=list(daily_counts.values()),
            mode='lines+markers',
            line=dict(color='#3498db', width=2),
            marker=dict(size=6),
            fill='tozeroy',
            fillcolor='rgba(52, 152, 219, 0.1)'
        )
    ])
    
    fig.update_layout(
        title="Daily Activity (Last 30 Days)",
        xaxis_title="Date",
        yaxis_title="Records Created",
        height=400,
        showlegend=False
    )
    
    return fig

# Initialize session states
if "file_uploader_key" not in st.session_state:
    st.session_state.file_uploader_key = 0
if "editing_record" not in st.session_state:
    st.session_state.editing_record = None

# --------------------------
# Main Application
# --------------------------
# Require login first
current_user = require_login()
user_config = load_user_config()

# Load form configurations
forms_lw = load_json("form_configs_enhanced.json")
forms_mpr = load_json("forms_mpr_configs_enhanced.json")

if not forms_lw and not forms_mpr:
    st.error("⚠️ No enhanced config files found. Please ensure form_configs_enhanced.json and forms_mpr_configs_enhanced.json exist.")
    st.stop()

# Form selection
col1, col2 = st.columns(2)
with col1:
    file_group = st.radio("📂 Select file group", ["LW FILES", "M&PR FILES"], horizontal=True)
with col2:
    cfg = forms_lw if file_group == "LW FILES" else forms_mpr
    form_code = st.selectbox("📋 Choose form", list(cfg.keys()), 
                           format_func=lambda x: f"{x} — {cfg[x].get('title','')}")

conf = cfg[form_code]
fields = conf.get("fields", [])

# Get user permissions for selected form
user_permissions = get_user_permissions(current_user["roles"], user_config, form_code, conf)

# Sidebar with user info
with st.sidebar:
    st.markdown("### User Information")
    st.write(f"**Name:** {current_user['name']}")
    st.write(f"**Department:** {current_user['department']}")
    st.write(f"**Roles:** {', '.join(current_user['roles'])}")
    st.write(f"**Email:** {current_user['email']}")
    
    # Show form-specific permissions
    st.markdown(f"### Permissions for {form_code}")
    for perm, allowed in user_permissions.items():
        icon = "✅" if allowed else "❌"
        st.caption(f"{icon} {perm.replace('_', ' ').title()}")
    
    # Show creatable forms summary
    creatable_forms = get_user_creatable_forms(current_user["roles"], user_config)
    st.markdown("### Form Creation Access")
    for group, forms in creatable_forms.items():
        if forms:
            st.success(f"{group}: {len(forms)} forms")
        else:
            st.error(f"{group}: No access")
    
    st.markdown("---")
    if st.button("Logout", type="secondary"):
        logout()

# Main interface
st.title("🗂️ IMS Enhanced - Role-Based Signature System")
st.markdown("*Secure document management with workflow-based digital signatures*")

# Tabs
tab_entry, tab_grid, tab_unsigned, tab_dashboard = st.tabs(
    ["📝 Form Entry", "📋 View & Edit", "⚠️ Pending Actions", "📊 Dashboard"]
)

with tab_entry:
    # Check if user can create entries for this specific form
    if not user_permissions.get("can_create", False):
        st.error("❌ You don't have permission to create this form.")
        st.markdown("### Why can't you create this form?")
        st.info("You can only create forms where you:")
        st.markdown("- Are a Junior Engineer (JE), OR")
        st.markdown("- Have administrative privileges (ADMIN/SSE/IMS), OR") 
        st.markdown("- Have signing authority for this specific form")
        
        # Show what signatures this form requires
        signatures_config = conf.get("signatures", {})
        if signatures_config:
            st.markdown("### This form requires signatures from:")
            for sig_name, sig_config in signatures_config.items():
                required_roles = sig_config.get("roles", [])
                st.markdown(f"- **{sig_name}**: {', '.join(required_roles)}")
        
        st.markdown("### Your current roles:")
        st.markdown(f"- {', '.join(current_user['roles'])}")
        
    else:
        # Show why user can create this form
        st.success("✅ You can create this form")
        show_permission_explanation(current_user["roles"], form_code, conf)
        
        st.subheader(f"📝 Form Entry — {conf.get('title', form_code)}")

        with st.form("entry_form"):
            st.markdown("### 📋 Form Data")
            values = {}
            
            # Arrange fields in columns
            num_cols = 2
            cols = st.columns(num_cols)
            for i, fld in enumerate(fields):
                with cols[i % num_cols]:
                    is_long = any(k in fld.lower() for k in ["remarks","details","description","action","cause"])
                    if is_long:
                        values[fld] = st.text_area(fld, height=100)
                    else:
                        values[fld] = st.text_input(fld)

            st.markdown("---")

            # Enhanced signature section
            sig_values = render_signature_section(form_code, current_user, conf)

            st.markdown("---")
            st.markdown("### 📎 File Attachments")
            uploads = st.file_uploader(
                "Attach file(s)", 
                type=None, 
                accept_multiple_files=True,
                key=f"entry_file_uploader_{st.session_state.file_uploader_key}",
                help="Upload supporting documents (Max 50MB per file)"
            )

            # Priority selection
            col1, col2 = st.columns(2)
            with col1:
                priority = st.selectbox("Priority", ["normal", "high", "urgent"], index=0)
            with col2:
                st.write("")  # Spacing

            submitted = st.form_submit_button("💾 Save Entry", type="primary")

        if submitted:
            # Validate required fields
            missing_fields = [f for f in fields if not values.get(f, "").strip()]
            if missing_fields:
                st.error(f"Please fill in required fields: {', '.join(missing_fields)}")
            else:
                paths, metadata = upload_files(form_code, uploads) if uploads else ([], [])
                
                # Process signatures with enhanced metadata
                processed_signatures = {}
                signature_comments = {}
                
                for sig_name, sig_value in sig_values.items():
                    if sig_name.endswith("_comment"):
                        continue  # Skip comment fields in main processing
                        
                    if isinstance(sig_value, bool) and sig_value:
                        # User is signing this
                        comment = sig_values.get(f"{sig_name}_comment", "")
                        processed_signatures[sig_name] = create_signature_entry(current_user, comment=comment)
                        if comment:
                            signature_comments[sig_name] = comment
                    elif isinstance(sig_value, dict):
                        # Existing signature
                        processed_signatures[sig_name] = sig_value
                
                # Calculate form status
                progress = get_form_signature_progress(processed_signatures, conf)
                
                payload = {
                    "file_type": file_group,
                    "form_code": form_code,
                    "data": values,
                    "signatures": processed_signatures,
                    "signature_comments": signature_comments,
                    "file_urls": paths,
                    "file_metadata": metadata,
                    "created_by": current_user["name"],
                    "created_by_email": current_user["email"],
                    "created_by_roles": current_user["roles"],
                    "created_by_department": current_user["department"],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "form_status": progress["status"],
                    "priority": priority
                }
                
                sb.table(TABLE_NAME).insert(payload).execute()
                st.success("✅ Entry saved successfully!")
                
                # Show signature progress
                if processed_signatures:
                    st.info(f"📈 Signature Progress: {progress['completed']}/{progress['total']} ({progress['progress']:.0f}%)")
                
                st.session_state.file_uploader_key += 1
                st.rerun()

with tab_grid:
    # Check if user is editing a record
    if st.session_state.editing_record:
        if can_user_edit_record(current_user, st.session_state.editing_record, user_config):
            form_config = forms_lw.get(st.session_state.editing_record['form_code']) or forms_mpr.get(st.session_state.editing_record['form_code'], {})
            render_edit_form(st.session_state.editing_record, form_config, current_user)
        else:
            st.error("❌ You don't have permission to edit this record.")
            st.session_state.editing_record = None
            st.rerun()
    else:
        st.subheader(f"📋 Records — {form_code}")

        # Enhanced filtering
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox("Filter by Status", 
                                       ["all", "draft", "in_progress", "complete"], 
                                       index=0)
        with col2:
            priority_filter = st.selectbox("Filter by Priority", 
                                         ["all", "normal", "high", "urgent"], 
                                         index=0)
        with col3:
            limit = st.number_input("Show records", min_value=10, max_value=500, value=50)

        # Build query
        query = sb.table(TABLE_NAME).select("*").eq("form_code", form_code).order("created_at", desc=True)
        
        if status_filter != "all":
            query = query.eq("form_status", status_filter)
        if priority_filter != "all":
            query = query.eq("priority", priority_filter)
            
        rows = query.limit(limit).execute().data or []

        if not rows:
            st.info("No records found matching the filters.")
        else:
            st.caption(f"Showing {len(rows)} records")
            
            # Enhanced action buttons with role-based permissions
            col1, col2, col3 = st.columns(3)
            
            with col1:
                csv_data = []
                for r in rows:
                    row_data = {
                        "ID": str(r.get("id", ""))[:8],
                        "Created": r.get("created_at", "")[:10],
                        "Created By": r.get("created_by", "Unknown"),
                        "Status": r.get("form_status", "draft").title(),
                        "Priority": r.get("priority", "normal").title()
                    }
                    # Add form data
                    data = r.get("data", {})
                    for field, value in data.items():
                        row_data[field] = str(value)[:100]  # Truncate long values
                    csv_data.append(row_data)
                
                if csv_data:
                    df_csv = pd.DataFrame(csv_data)
                    csv = df_csv.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "⬇️ Export CSV", 
                        csv,
                        file_name=f"{form_code}_{datetime.now().strftime('%Y%m%d')}.csv", 
                        mime="text/csv",
                        type="secondary"
                    )
            
            with col2:
                if st.button("🔄 Refresh", type="secondary"):
                    st.rerun()
            
            with col3:
                st.write("")  # Spacing for layout
            
            # Create enhanced grid view
            flat = []
            for r in rows:
                d = r.get("data") or {}
                sig = r.get("signatures") or {}
                progress = get_form_signature_progress(sig, conf)
                
                row = {
                    "ID": str(r.get("id", ""))[:8],
                    "Created": r.get("created_at", "")[:10],
                    "Created By": r.get("created_by", "Unknown"),
                    "Department": r.get("created_by_department", ""),
                    "Status": r.get("form_status", "draft").title(),
                    "Priority": r.get("priority", "normal").title(),
                    "Progress": f"{progress['completed']}/{progress['total']}"
                }
                
                # Add field data (first few fields only for grid view)
                for i, f in enumerate(fields[:3]):  # Show first 3 fields
                    row[f] = str(d.get(f, ""))[:50]  # Truncate long values
                
                # Show signature status (only visible ones)
                visible_sigs = get_visible_signatures(form_code, current_user["roles"], conf)
                for s in visible_sigs[:2]:  # Show first 2 signatures
                    row[f"✔ {s}"] = get_signature_status_display(sig, s)
                
                # File count
                file_meta = r.get("file_metadata", [])
                row["Files"] = f"{len(file_meta)} files" if file_meta else "No files"
                
                flat.append(row)

            df = pd.DataFrame(flat)
            
            # Display with enhanced styling
            st.dataframe(df, use_container_width=True, height=400)

            # Detailed view with individual actions
            st.markdown("### 🔍 Detailed View")
            for r in rows[:10]:  # Show first 10 records in detail
                progress = get_form_signature_progress(r.get("signatures", {}), conf)
                
                # Status indicator
                if progress["status"] == "complete":
                    status_color = "🟢"
                elif progress["status"] == "in_progress":
                    status_color = "🟡"
                else:
                    status_color = "🔴"
                    
                priority_color = {"normal": "🔵", "high": "🟠", "urgent": "🔴"}.get(r.get("priority", "normal"), "🔵")
                
                # Permission indicators
                can_edit = can_user_edit_record(current_user, r, user_config)
                can_delete = can_user_delete_record(current_user, r, user_config)
                edit_icon = "✏️" if can_edit else ""
                delete_icon = "🗑️" if can_delete else ""
                
                with st.expander(f"{status_color} {priority_color} {edit_icon} {delete_icon} **{form_code}** — {r.get('created_at','')[:10]} by {r.get('created_by','Unknown')}"):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        # Show form data
                        st.markdown("**📋 Form Data:**")
                        data_items = list((r.get("data") or {}).items())
                        if data_items:
                            df_view = pd.DataFrame(data_items, columns=["Field", "Value"])
                            st.dataframe(df_view, use_container_width=True)
                    
                    with col2:
                        # Show metadata
                        st.markdown("**ℹ️ Metadata:**")
                        st.caption(f"**ID:** {str(r.get('id', ''))[:8]}")
                        st.caption(f"**Status:** {r.get('form_status', 'draft').title()}")
                        st.caption(f"**Priority:** {r.get('priority', 'normal').title()}")
                        st.caption(f"**Progress:** {progress['completed']}/{progress['total']} signatures")
                        st.caption(f"**Department:** {r.get('created_by_department', 'Unknown')}")
                        
                        # Simplified Action buttons for individual records
                        st.markdown("**Actions:**")
                        
                        if can_edit:
                            if st.button(f"✏️ Edit", key=f"edit_{r['id']}", type="secondary", use_container_width=True):
                                st.session_state.editing_record = r
                                st.rerun()
                        
                        if can_delete:
                            # Simplified delete with modal confirmation
                            delete_key = f"delete_confirm_{r['id']}"
                            
                            if delete_key not in st.session_state:
                                st.session_state[delete_key] = False
                            
                            if not st.session_state[delete_key]:
                                if st.button(f"🗑️ Delete", key=f"del_btn_{r['id']}", type="secondary", use_container_width=True):
                                    st.session_state[delete_key] = True
                                    st.rerun()
                            else:
                                # Show confirmation dialog
                                st.error("⚠️ **Confirm Deletion**")
                                st.caption(f"Delete {form_code} created on {r.get('created_at', '')[:10]}?")
                                
                                col_yes, col_no = st.columns(2)
                                with col_yes:
                                    if st.button("✅ Yes, Delete", key=f"confirm_del_{r['id']}", type="primary"):
                                        # Perform deletion
                                        success = delete_record_with_files(r["id"], r.get("file_metadata", []))
                                        
                                        if success:
                                            st.success("✅ Record deleted successfully!")
                                            # Clear the confirmation state
                                            st.session_state[delete_key] = False
                                            # Small delay to show success message
                                            import time
                                            time.sleep(1)
                                            st.rerun()
                                        else:
                                            st.error("❌ Failed to delete record. Please try again.")
                                            st.session_state[delete_key] = False
                                
                                with col_no:
                                    if st.button("❌ Cancel", key=f"cancel_del_{r['id']}", type="secondary"):
                                        st.session_state[delete_key] = False
                                        st.rerun()

                    # Show signatures
                    st.markdown("**✍️ Signature Status:**")
                    signatures = r.get("signatures", {})
                    visible_sigs = get_visible_signatures(form_code, current_user["roles"], conf)
                    
                    if visible_sigs:
                        for sig_name in visible_sigs:
                            sig_data = signatures.get(sig_name, {})
                            if isinstance(sig_data, dict) and sig_data.get("signed", False):
                                signed_by = sig_data.get("signed_by_name", "Unknown")
                                signed_at = sig_data.get("signed_at", "Unknown")[:16]
                                department = sig_data.get("department", "")
                                comment = sig_data.get("comment", "")
                                
                                st.success(f"✅ **{sig_name}** - {signed_by} ({department}) on {signed_at}")
                                if comment:
                                    st.caption(f"Comment: {comment}")
                            else:
                                st.warning(f"❌ **{sig_name}** - Pending")
                    else:
                        st.info("No signatures visible to your role")

                    # Show files
                    if r.get("file_metadata"):
                        st.markdown("**📎 Attached Files:**")
                        for m in r["file_metadata"]:
                            url = get_file_download_url(m["storage_path"], m["original_name"])
                            file_size = m.get("file_size", 0)
                            st.markdown(f"- [{m['original_name']}]({url}) ({file_size:,} bytes)")

with tab_unsigned:
    st.subheader("⚠️ Pending Actions")
    st.markdown("Forms requiring your signature or attention")
    
    # Get all records that might need user's signature
    try:
        all_records = sb.table(TABLE_NAME).select("*").order("created_at", desc=True).execute().data or []
    except Exception as e:
        st.error(f"Error fetching records: {e}")
        all_records = []
    
    pending_records = []
    user_roles = current_user["roles"]
    
    for record in all_records:
        form_config = forms_lw.get(record.get("form_code")) or forms_mpr.get(record.get("form_code"), {})
        if not form_config:
            continue
            
        signatures = record.get("signatures", {})
        signatures_config = form_config.get("signatures", {})
        
        # Check if user can sign any signature in this record
        for sig_name, sig_config in signatures_config.items():
            if can_user_sign(record.get("form_code", ""), sig_name, user_roles, signatures, form_config):
                pending_records.append({
                    "record": record,
                    "signature": sig_name,
                    "form_config": form_config
                })
                break  # Only add record once even if multiple signatures pending
    
    if not pending_records:
        st.info("🎉 No pending actions! All forms requiring your signature are complete.")
    else:
        st.warning(f"📋 {len(pending_records)} forms require your attention")
        
        for item in pending_records:
            record = item["record"]
            sig_name = item["signature"]
            form_config = item["form_config"]
            
            with st.expander(f"🔔 **{record.get('form_code')}** — {record.get('created_at', '')[:10]} by {record.get('created_by', 'Unknown')}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    # Show form data summary
                    st.markdown("**📋 Form Data:**")
                    data = record.get("data", {})
                    for field, value in list(data.items())[:5]:  # Show first 5 fields
                        st.caption(f"**{field}:** {str(value)[:100]}")
                    
                    if len(data) > 5:
                        st.caption(f"... and {len(data) - 5} more fields")
                
                with col2:
                    st.markdown("**Required Signature:**")
                    st.info(f"🖊️ {sig_name}")
                    
                    # Quick signature form
                    with st.form(f"quick_sign_{record['id']}"):
                        sign_comment = st.text_area("Signature Comment (optional)", height=60)
                        sign_now = st.form_submit_button("✏️ Sign Now", type="primary")
                    
                    if sign_now:
                        # Create signature entry
                        new_signature = create_signature_entry(current_user, comment=sign_comment)
                        
                        # Update record with new signature
                        updated_signatures = record.get("signatures", {}).copy()
                        updated_signatures[sig_name] = new_signature
                        
                        # Update signature comments
                        updated_comments = record.get("signature_comments", {}).copy()
                        if sign_comment:
                            updated_comments[sig_name] = sign_comment
                        
                        # Calculate new form status
                        progress = get_form_signature_progress(updated_signatures, form_config)
                        
                        try:
                            sb.table(TABLE_NAME).update({
                                "signatures": updated_signatures,
                                "signature_comments": updated_comments,
                                "form_status": progress["status"],
                                "updated_at": datetime.now(timezone.utc).isoformat(),
                                "updated_by": current_user["name"]
                            }).eq("id", record["id"]).execute()
                            
                            st.success(f"✅ Signed successfully!")
                            st.info(f"📈 Form Status: {progress['status'].title()} ({progress['completed']}/{progress['total']} signatures)")
                            st.rerun()
                            
                        except Exception as e:
                            st.error(f"Error signing form: {e}")

with tab_dashboard:
    st.subheader("📊 System Dashboard")
    st.markdown("Overview of all forms and records in the system")
    
    # Get all system data
    all_data = get_all_system_data()
    
    if not all_data:
        st.warning("No data found in the system.")
    else:
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Records", len(all_data))
        
        with col2:
            draft_count = len([r for r in all_data if r.get("form_status") == "draft"])
            st.metric("Draft Forms", draft_count)
        
        with col3:
            complete_count = len([r for r in all_data if r.get("form_status") == "complete"])
            st.metric("Completed Forms", complete_count)
        
        with col4:
            urgent_count = len([r for r in all_data if r.get("priority") == "urgent"])
            st.metric("Urgent Items", urgent_count)
        
        st.markdown("---")
        
        # Charts section
        col1, col2 = st.columns(2)
        
        with col1:
            # Priority chart
            priority_fig = create_priority_chart(all_data)
            if priority_fig:
                st.plotly_chart(priority_fig, use_container_width=True)
        
        with col2:
            # Status chart
            status_fig = create_status_chart(all_data)
            if status_fig:
                st.plotly_chart(status_fig, use_container_width=True)
        
        # Second row of charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Department chart
            dept_fig = create_department_chart(all_data)
            if dept_fig:
                st.plotly_chart(dept_fig, use_container_width=True)
        
        with col2:
            # Daily activity chart
            activity_fig = create_daily_activity_chart(all_data)
            if activity_fig:
                st.plotly_chart(activity_fig, use_container_width=True)
        
        # Form type distribution (full width)
        st.markdown("### Form Type Distribution")
        form_fig = create_form_type_chart(all_data)
        if form_fig:
            st.plotly_chart(form_fig, use_container_width=True)
        
        st.markdown("---")
        
        # Recent activity table
        st.markdown("### Recent Activity (Last 10 Records)")
        recent_data = all_data[:10]
        
        if recent_data:
            recent_df_data = []
            for record in recent_data:
                recent_df_data.append({
                    "ID": str(record.get("id", ""))[:8],
                    "Form Code": record.get("form_code", "Unknown"),
                    "Created": record.get("created_at", "")[:10],
                    "Created By": record.get("created_by", "Unknown"),
                    "Department": record.get("created_by_department", "Unknown"),
                    "Status": record.get("form_status", "draft").title(),
                    "Priority": record.get("priority", "normal").title()
                })
            
            recent_df = pd.DataFrame(recent_df_data)
            st.dataframe(recent_df, use_container_width=True)
        
        st.markdown("---")
        
        # Export options
        st.markdown("### Export System Data")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Export All Records (CSV)", type="secondary"):
                # Create comprehensive CSV
                export_data = []
                for record in all_data:
                    row = {
                        "ID": str(record.get("id", "")),
                        "Form Code": record.get("form_code", ""),
                        "File Type": record.get("file_type", ""),
                        "Created": record.get("created_at", ""),
                        "Created By": record.get("created_by", ""),
                        "Department": record.get("created_by_department", ""),
                        "Status": record.get("form_status", ""),
                        "Priority": record.get("priority", ""),
                        "Updated": record.get("updated_at", ""),
                        "Files Count": len(record.get("file_metadata", []))
                    }
                    
                    # Add form data fields
                    data = record.get("data", {})
                    for field, value in data.items():
                        row[f"Data_{field}"] = str(value)
                    
                    # Add signature status
                    signatures = record.get("signatures", {})
                    for sig_name, sig_data in signatures.items():
                        if isinstance(sig_data, dict) and sig_data.get("signed"):
                            row[f"Sig_{sig_name}"] = f"✅ {sig_data.get('signed_by_name', 'Unknown')}"
                        else:
                            row[f"Sig_{sig_name}"] = "❌ Pending"
                    
                    export_data.append(row)
                
                if export_data:
                    export_df = pd.DataFrame(export_data)
                    csv_data = export_df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "⬇️ Download CSV",
                        csv_data,
                        file_name=f"ims_system_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv"
                    )
        
        with col2:
            # Filter options for dashboard
            st.markdown("**Filter Dashboard:**")
            dashboard_status = st.multiselect(
                "Status", 
                ["draft", "in_progress", "complete"], 
                default=["draft", "in_progress", "complete"],
                key="dash_status"
            )
            dashboard_priority = st.multiselect(
                "Priority", 
                ["normal", "high", "urgent"], 
                default=["normal", "high", "urgent"],
                key="dash_priority"
            )
        
        with col3:
            st.markdown("**Quick Stats:**")
            if dashboard_status and dashboard_priority:
                filtered_data = [
                    r for r in all_data 
                    if r.get("form_status", "draft") in dashboard_status 
                    and r.get("priority", "normal") in dashboard_priority
                ]
                st.info(f"Filtered: {len(filtered_data)} records")
                
                if filtered_data:
                    avg_completion = sum(
                        len([s for s in r.get("signatures", {}).values() 
                             if isinstance(s, dict) and s.get("signed", False)]) 
                        for r in filtered_data
                    ) / len(filtered_data) if filtered_data else 0
                    st.metric("Avg Signatures", f"{avg_completion:.1f}")

# --------------------------
# Report Generator (Enhanced for Dashboard)
# --------------------------
# Optional: try to use weasyprint for PDF output
try:
    from weasyprint import HTML, CSS
    _WEASY = True
except Exception:
    _WEASY = False

def _escape_html(s):
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>"))

def build_report_html(rows: List[Dict], report_title: str, show_compact: bool = True):
    """
    Build an HTML string for the report.
    - rows: list of DB rows (dict)
    - report_title: heading text
    - show_compact: if True, produce landscape with compact table + stacked details
    """
    # Basic CSS: landscape if compact
    page_css = "@page { size: A4 landscape; margin: 10mm; }" if show_compact else "@page { size: A4 portrait; margin: 12mm; }"
    css = f"""
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; color: #222; }}
    h1 {{ text-align: center; font-size: 18px; margin-bottom: 8px; }}
    .meta {{ font-size: 12px; color: #444; margin-bottom: 12px; }}
    table.main {{ width: 100%; border-collapse: collapse; margin-bottom: 14px; }}
    table.main th, table.main td {{ border: 1px solid #ddd; padding: 6px; font-size: 11px; }}
    table.record-fields {{ width: 100%; border-collapse: collapse; margin: 6px 0 10px 0; }}
    .fieldname {{ width: 28%; background:#f6f6f6; padding:6px; font-weight:600; vertical-align:top; }}
    .fieldval {{ width: 72%; padding:6px; vertical-align:top; }}
    .sign-row {{ padding:4px 0; font-size:12px; }}
    .attachment {{ font-size:11px; color:#333; }}
    {page_css}
    """
    title_html = f"<h1>{_escape_html(report_title)}</h1>"
    
    # Get all unique form codes to determine fields
    form_codes = list(set(r.get("form_code") for r in rows))
    all_forms = {**forms_lw, **forms_mpr}
    
    # Use fields from the first form or common fields
    sample_fields = []
    if form_codes:
        sample_form = all_forms.get(form_codes[0], {})
        sample_fields = sample_form.get("fields", [])[:3]  # First 3 fields
    
    # Compact table header
    head_cols = ["ID", "Form", "Created", "Created By", "Status", "Priority"] + sample_fields
    head_cells = "".join(f"<th>{_escape_html(c)}</th>" for c in head_cols)
    
    table_rows_html = ""
    for r in rows:
        d = r.get("data") or {}
        # Basic info
        basic = [
            _escape_html(str(r.get("id",""))[:8]),
            _escape_html(r.get("form_code", "")),
            _escape_html(r.get("created_at","")[:10]),
            _escape_html(r.get("created_by","")),
            _escape_html(r.get("form_status","")),
            _escape_html(r.get("priority","")),
        ]
        
        # Add form-specific fields
        for f in sample_fields:
            v = d.get(f, "")
            s = str(v)
            if len(s) > 140:
                s = s[:136] + "..."
            basic.append(_escape_html(s))
        
        table_rows_html += "<tr>" + "".join(f"<td>{c}</td>" for c in basic) + "</tr>"

    # Build details section
    details_html = ""
    for r in rows:
        details_html += "<div class='record' style='margin-bottom:14px;'>"
        details_html += f"<div class='meta'><b>{_escape_html(str(r.get('form_code','')))} — {_escape_html(str(r.get('id',''))[:8])}</b> &nbsp; Created: {_escape_html(r.get('created_at',''))} &nbsp; By: {_escape_html(r.get('created_by',''))}</div>"
        
        # Get form config for this record
        form_config = all_forms.get(r.get("form_code"), {})
        record_fields = form_config.get("fields", [])
        
        # Fields table
        if record_fields:
            details_html += "<table class='record-fields'>"
            for f in record_fields:
                v = r.get("data",{}).get(f,"")
                details_html += f"<tr><td class='fieldname'>{_escape_html(f)}</td><td class='fieldval'>{_escape_html(v)}</td></tr>"
            details_html += "</table>"
        
        # Signatures
        details_html += "<div><b>Signatures</b><table style='width:100%;'>"
        sigcfg = form_config.get("signatures", {})
        current_sigs = r.get("signatures", {}) or {}
        
        for sname, scfg in (sigcfg.items() if isinstance(sigcfg, dict) else []):
            sdata = current_sigs.get(sname, {})
            if isinstance(sdata, dict) and sdata.get("signed", False):
                who = _escape_html(sdata.get("signed_by_name",""))
                dept = _escape_html(sdata.get("department",""))
                when = _escape_html(sdata.get("signed_at","")[:16])
                comment = _escape_html(sdata.get("comment",""))
                details_html += f"<tr><td style='width:30%;font-weight:600;padding:6px'>{_escape_html(sname)}</td><td style='padding:6px'>✅ {who} ({dept}) — {when}"
                if comment:
                    details_html += f"<div style='font-size:11px;color:#333;margin-top:4px'>Comment: {comment}</div>"
                details_html += "</td></tr>"
            else:
                details_html += f"<tr><td style='width:30%;font-weight:600;padding:6px'>{_escape_html(sname)}</td><td style='padding:6px'>❌ Pending</td></tr>"
        details_html += "</table></div>"
        
        # Files
        if r.get("file_metadata"):
            details_html += "<div style='margin-top:8px;'><b>Attachments</b><ul>"
            for fm in r.get("file_metadata", []):
                details_html += f"<li class='attachment'>{_escape_html(fm.get('original_name'))} ({fm.get('file_size',0)} bytes)</li>"
            details_html += "</ul></div>"

        details_html += "</div><hr style='border:none;border-top:1px solid #eee;margin:10px 0;'>"

    html = f"""
    <html><head><meta charset='utf-8'><style>{css}</style></head>
    <body>
      {title_html}
      <table class='main'>
        <thead><tr>{head_cells}</tr></thead>
        <tbody>{table_rows_html}</tbody>
      </table>
      {details_html}
    </body></html>
    """
    return html

# Add report generator in dashboard (dedented, top-level in module)
st.markdown("---")
st.markdown("### 📄 Generate System Report")

col1, col2, col3 = st.columns(3)

with col1:
    report_status = st.multiselect(
        "Include Status", 
        ["draft", "in_progress", "complete"], 
        default=["in_progress", "complete"],
        key="report_status"
    )

with col2:
    report_priority = st.multiselect(
        "Include Priority", 
        ["normal", "high", "urgent"], 
        default=["normal", "high", "urgent"],
        key="report_priority"
    )

with col3:
    report_limit = st.number_input(
        "Max records", 
        min_value=1, 
        max_value=1000, 
        value=200,
        key="report_limit"
    )

report_style = st.selectbox(
    "Report layout", 
    ["Compact (landscape)", "Detailed (portrait)"],
    key="report_style"
)

# --- Replace the existing "Generate System Report" handler with this block ---

if st.button("📊 Generate System Report", type="primary"):
    # Ensure we have data available
    try:
        all_data_local = all_data if 'all_data' in locals() else get_all_system_data()
    except Exception:
        all_data_local = get_all_system_data()

    filtered_data = [
        r for r in all_data_local
        if (r.get("form_status", "draft") in report_status)
        and (r.get("priority", "normal") in report_priority)
    ][:report_limit]

    if not filtered_data:
        st.warning("No records match the selected filters.")
    else:
        title = f"IMS System Report — {len(filtered_data)} records"
        html = build_report_html(filtered_data, title, show_compact=(report_style.startswith("Compact")))

        # Always offer the HTML download (previous behavior)
        try:
            html_bytes = html.encode("utf-8")
            st.download_button(
                "📥 Download HTML Report",
                html_bytes,
                file_name=f"ims_system_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html",
                mime="text/html",
                key="download_html_report"
            )
        except Exception as e:
            st.warning(f"Could not prepare HTML download: {e}")

        # If WeasyPrint is available, try to create a PDF and offer it too.
        if _WEASY:
            try:
                pdf = HTML(string=html).write_pdf()
                st.download_button(
                    "📥 Download PDF Report",
                    pdf,
                    file_name=f"ims_system_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    key="download_pdf_report"
                )
                st.success("📊 System report PDF ready for download!")
            except Exception as e:
                st.warning(f"PDF generation failed: {e}. You can still download the HTML report.")
        else:
            st.info("WeasyPrint not available. Download HTML report and convert to PDF externally if needed.")

# --------------------------
# Footer
# --------------------------
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.caption("IMS Enhanced v2.3")
with col2:
    st.caption("Complete Dashboard & Reporting System")
with col3:
    st.caption(f"Logged in as: {current_user['name']}")
