# 🚀 Nigerian Road Risk Reporter - Deployment Guide

## 📋 Overview

This guide provides deployment instructions for all three versions of the Nigerian Road Risk Reporter application:

1. **`streamlit_app_minimal.py`** - Minimal version for local development
2. **`streamlit_app_secure.py`** - Enhanced version with advanced security
3. **`streamlit_app_cloud.py`** - Streamlit Cloud optimized version

## 🎯 Quick Start

### Local Development (Recommended for testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Run minimal version (fastest startup)
streamlit run streamlit_app_minimal.py

# Run secure version (full features)
streamlit run streamlit_app_secure.py

# Run cloud version (optimized for deployment)
streamlit run streamlit_app_cloud.py
```

### Streamlit Cloud Deployment

1. **Upload to GitHub** (already done)
2. **Connect to Streamlit Cloud**
3. **Deploy using `streamlit_app_cloud.py`**

## 📦 Dependencies

### Required Dependencies
```txt
streamlit>=1.28.0
pandas>=2.1.0
plotly>=5.17.0
bcrypt>=4.0.1
pyotp>=2.9.0
numpy>=1.26.0
```

### Optional Dependencies
```txt
qrcode>=7.4.0  # For 2FA QR codes
pillow>=10.0.0  # For image processing
```

## 🔧 App Versions Comparison

| Feature | Minimal | Secure | Cloud |
|---------|---------|--------|-------|
| **Core Functionality** | ✅ | ✅ | ✅ |
| **Nigerian Roads Data** | ✅ | ✅ | ✅ |
| **24h Risk Reports** | ✅ | ✅ | ✅ |
| **3m Road Conditions** | ✅ | ✅ | ✅ |
| **AI Insights** | ✅ | ✅ | ✅ |
| **Advanced Security** | ⚠️ Basic | ✅ Full | ✅ Full |
| **2FA Authentication** | ❌ | ✅ | ✅ |
| **Rate Limiting** | ⚠️ Basic | ✅ Advanced | ✅ Advanced |
| **Session Management** | ⚠️ Basic | ✅ Advanced | ✅ Cloud-optimized |
| **File Upload Security** | ⚠️ Basic | ✅ Advanced | ✅ Cloud-optimized |
| **Streamlit Cloud Ready** | ⚠️ | ⚠️ | ✅ |

## 🌐 Streamlit Cloud Deployment

### Step 1: Prepare Repository
```bash
# Ensure all files are committed
git add .
git commit -m "Ready for Streamlit Cloud deployment"
git push origin main
```

### Step 2: Deploy on Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Connect your GitHub repository
3. Set the main file path to: `streamlit_app_cloud.py`
4. Deploy

### Step 3: Configure Environment Variables (Optional)
```bash
# In Streamlit Cloud settings
SECRET_KEY=your_secret_key_here
ADMIN_EMAIL=admin@example.com
```

## 🔒 Security Configuration

### For Production Deployment
1. **Change default passwords**
2. **Set up proper admin accounts**
3. **Configure environment variables**
4. **Enable HTTPS (automatic on Streamlit Cloud)**

### Security Features Available
- ✅ Password hashing with bcrypt
- ✅ Two-factor authentication (TOTP)
- ✅ Rate limiting and account lockout
- ✅ Session management with timeout
- ✅ Input validation and sanitization
- ✅ SQL injection protection
- ✅ XSS protection
- ✅ File upload security

## 📊 Database Setup

### Automatic Setup
The application automatically creates required databases:
- `users.db` - User accounts and authentication
- `nigerian_roads.db` - Nigerian roads data and reports

### Manual Database Reset
```bash
# Remove existing databases (if needed)
rm users.db nigerian_roads.db

# Restart application to recreate databases
streamlit run streamlit_app_cloud.py
```

## 🧪 Testing

### Run Compatibility Test
```bash
python compatibility_test.py
```

### Test All App Versions
```bash
# Test minimal version
streamlit run streamlit_app_minimal.py

# Test secure version
streamlit run streamlit_app_secure.py

# Test cloud version
streamlit run streamlit_app_cloud.py
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Kill existing Streamlit processes
pkill -f streamlit

# Or use different port
streamlit run streamlit_app_cloud.py --server.port 8502
```

#### 2. Database Errors
```bash
# Reset databases
rm *.db
streamlit run streamlit_app_cloud.py
```

#### 3. Import Errors
```bash
# Install missing dependencies
pip install -r requirements.txt

# Check compatibility
python compatibility_test.py
```

#### 4. Streamlit Cloud Issues
- Ensure `streamlit_app_cloud.py` is the main file
- Check all dependencies are in `requirements.txt`
- Verify no external services are required

### Performance Optimization

#### For Local Development
- Use `streamlit_app_minimal.py` for fastest startup
- Use `streamlit_app_secure.py` for full features

#### For Production
- Use `streamlit_app_cloud.py` for Streamlit Cloud
- Optimize database queries
- Enable caching where appropriate

## 📈 Monitoring

### Application Logs
- Check Streamlit Cloud logs for deployment issues
- Monitor user activity through admin dashboard
- Review security audit logs

### Performance Metrics
- Response times
- Database query performance
- User engagement metrics

## 🔄 Updates and Maintenance

### Regular Updates
1. **Security patches** - Update dependencies regularly
2. **Feature updates** - Deploy new features through GitHub
3. **Database maintenance** - Monitor database size and performance

### Backup Strategy
- **Code**: GitHub repository
- **Data**: Regular database exports
- **Configuration**: Environment variables

## 📞 Support

### Documentation
- `README.md` - Project overview
- `ENHANCEMENT_SUMMARY.md` - Feature documentation
- `SECURITY_COMPARISON.md` - Security analysis

### Issues and Bugs
1. Check compatibility test: `python compatibility_test.py`
2. Review error logs
3. Test with different app versions
4. Report issues with detailed error messages

## ✅ Deployment Checklist

### Pre-Deployment
- [ ] All tests pass (`python compatibility_test.py`)
- [ ] Dependencies updated (`requirements.txt`)
- [ ] Security features configured
- [ ] Database initialized
- [ ] Environment variables set

### Post-Deployment
- [ ] Application loads successfully
- [ ] User registration works
- [ ] Report submission functions
- [ ] Admin features accessible
- [ ] Security features active

### Production Checklist
- [ ] HTTPS enabled
- [ ] Admin accounts created
- [ ] Monitoring configured
- [ ] Backup strategy in place
- [ ] Documentation updated

---

**🎉 Your Nigerian Road Risk Reporter is now ready for deployment!**

Choose the appropriate app version based on your deployment environment and requirements. 