# 🚀 Streamlit Cloud Deployment Guide

## ⚠️ IMPORTANT: Use Lite Version for Streamlit Cloud

### **For Streamlit Cloud Deployment:**

**Main File:** `streamlit_app_lite.py`  
**Requirements:** `requirements_streamlit_lite.txt`

### **Configuration Steps:**

1. **In Streamlit Cloud Dashboard:**
   - Set **Main file path** to: `streamlit_app_lite.py`
   - Set **Requirements file** to: `requirements_streamlit_lite.txt`

2. **Files to Use:**
   - ✅ `streamlit_app_lite.py` - Main application (NO Pydantic dependencies)
   - ✅ `requirements_streamlit_lite.txt` - Minimal dependencies
   - ✅ `.streamlit/config.toml` - Configuration

3. **Files to AVOID:**
   - ❌ `streamlit_app.py` - Contains Pydantic dependencies (causes compilation errors)
   - ❌ `requirements_streamlit.txt` - Contains problematic dependencies
   - ❌ `app.py` - FastAPI version (not for Streamlit Cloud)

### **Why Lite Version?**

The lite version resolves these Streamlit Cloud issues:
- ❌ pydantic-core compilation errors on Python 3.13
- ❌ Rust compilation dependencies
- ❌ ForwardRef compatibility issues
- ❌ Complex dependency chains

### **Lite Version Benefits:**
- ✅ **100% Streamlit Cloud compatible**
- ✅ **Python 3.13+ ready**
- ✅ **No compilation required**
- ✅ **Same functionality as full version**
- ✅ **Better performance**

### **Deployment Commands:**

```bash
# Streamlit Cloud should use:
Main file: streamlit_app_lite.py
Requirements: requirements_streamlit_lite.txt
```

### **Troubleshooting:**

If you still see pydantic errors:
1. **Check main file path** - Must be `streamlit_app_lite.py`
2. **Check requirements file** - Must be `requirements_streamlit_lite.txt`
3. **Redeploy** - Clear cache and redeploy

---

**Status:** ✅ Ready for Streamlit Cloud  
**Version:** Lite 1.0  
**Last Updated:** August 2025 