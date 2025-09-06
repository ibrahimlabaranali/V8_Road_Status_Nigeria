# 🚧 Road Status Reporter - Minimal App

A simple, clean, and lightweight road status reporting application built with Streamlit, featuring integrated admin functionality.

## ✨ Features

- **📊 Dashboard**: Overview of reports with key metrics
- **📋 Reports**: View and filter all road reports
- **📝 Create Reports**: Submit new road condition reports
- **🗺️ Map View**: Interactive map showing report locations
- **📈 Analytics**: Charts and insights about reports
- **🔐 Simple Authentication**: Demo login system
- **🔧 Admin Panel**: Integrated admin functionality for user and report management

## 🔑 Admin Features

- **User Management**: View, suspend, and activate users
- **Report Moderation**: Verify, resolve, and delete reports
- **System Logs**: View admin actions and system activity
- **Super Admin Access**: View all system logs and comprehensive activity tracking
- **User Logs**: View detailed logs for individual users

## 🚀 Quick Start

### Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements_minimal.txt
   ```

2. **Run the app:**
   ```bash
   python start_minimal.py
   ```
   
   Or directly with Streamlit:
   ```bash
   streamlit run streamlit_app_minimal.py
   ```

3. **Open your browser:**
   Navigate to `http://localhost:8501`

### Admin Access

- **Regular User**: Enter any username and password
- **Admin Access**: Use `admin` / `admin` for full admin privileges
- **Super Admin**: Same as admin - can view all system logs

### Streamlit Cloud Deployment

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Add minimal road status app with admin features"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud:**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Connect your GitHub repository
   - Set the main file path to: `streamlit_app_minimal.py`
   - Deploy!

## 📁 File Structure

```
├── streamlit_app_minimal.py    # Main application with admin features
├── requirements_minimal.txt    # Python dependencies
├── start_minimal.py           # Local startup script
├── README_minimal.md          # This file
└── .gitignore                # Git ignore file
```

## 🔧 Configuration

The app is pre-configured with:
- **Port**: 8501 (default Streamlit port)
- **Layout**: Wide layout for better dashboard experience
- **Theme**: Clean, professional appearance
- **Demo Data**: Nigerian road reports for testing
- **Admin Integration**: Built-in admin panel and user management

## 📊 Demo Data

The app includes realistic demo data:
- 25 sample road reports
- Nigerian states and locations
- Various road conditions and risk levels
- Different report statuses
- Sample users and admin logs

## 🎯 Use Cases

- **Citizens**: Report road issues in their area
- **Local Government**: Monitor road conditions
- **Transport Authorities**: Track infrastructure needs
- **Emergency Services**: Identify high-risk areas
- **Administrators**: Manage users and moderate reports
- **Super Admins**: Monitor all system activity

## 🔒 Security & Admin Features

- **Demo Mode**: Simple authentication for demonstration
- **Admin Panel**: Integrated user and report management
- **User Logs**: Admins can view all logs by user
- **Super Admin**: Access to all system logs and activity
- **No Database**: Uses in-memory demo data
- **No External APIs**: Self-contained application

## 🚀 Deployment Options

### Streamlit Cloud (Recommended)
- Free hosting
- Automatic deployments
- Easy GitHub integration
- Professional URLs

### Local/On-Premise
- Full control
- Custom domain
- Internal network access
- Custom configurations

### Other Cloud Platforms
- Heroku
- AWS
- Google Cloud
- Azure

## 📱 Mobile Compatibility

- Responsive design
- Mobile-friendly interface
- Touch-optimized controls
- Works on all devices

## 🆘 Troubleshooting

### Common Issues

1. **Port already in use:**
   ```bash
   # Kill process on port 8501
   lsof -ti:8501 | xargs kill -9
   ```

2. **Missing dependencies:**
   ```bash
   pip install -r requirements_minimal.txt
   ```

3. **Streamlit not found:**
   ```bash
   pip install streamlit
   ```

### Getting Help

- Check the Streamlit documentation
- Review error messages in the terminal
- Ensure all dependencies are installed
- Verify Python version (3.8+ recommended)

## 🔄 Updates

To update the app:
1. Pull latest changes: `git pull origin main`
2. Restart the application
3. Clear browser cache if needed

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the code comments

---

**Made with ❤️ using Streamlit**

**🔧 Now with Integrated Admin Features!**
