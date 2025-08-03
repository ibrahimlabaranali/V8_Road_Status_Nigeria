#!/usr/bin/env python3
"""
Analytics Dashboard for Nigerian Road Risk Reporter
Interactive charts, filters, and export functionality
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import io
import base64
from typing import Dict, List, Optional

# Custom CSS for analytics dashboard
ANALYTICS_CSS = """
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        text-align: center;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .metric-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    .chart-container {
        background-color: white;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .filter-section {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
"""

def get_reports_data(filters: Dict = None) -> pd.DataFrame:
    """Get reports data from database with optional filters"""
    try:
        conn = sqlite3.connect('users.db')
        
        # Build query with filters
        query = """
            SELECT 
                r.id,
                r.risk_type,
                r.description,
                r.location,
                r.latitude,
                r.longitude,
                r.source_type,
                r.status,
                r.created_at,
                r.upvotes,
                r.advice,
                r.risk_level,
                u.full_name as reporter_name,
                u.role as reporter_role
            FROM risk_reports r
            LEFT JOIN users u ON r.user_id = u.id
        """
        
        params = []
        where_conditions = []
        
        if filters:
            if filters.get('date_from'):
                where_conditions.append("r.created_at >= ?")
                params.append(filters['date_from'])
            
            if filters.get('date_to'):
                where_conditions.append("r.created_at <= ?")
                params.append(filters['date_to'])
            
            if filters.get('risk_type') and filters['risk_type'] != 'All':
                where_conditions.append("r.risk_type = ?")
                params.append(filters['risk_type'])
            
            if filters.get('location'):
                where_conditions.append("r.location LIKE ?")
                params.append(f"%{filters['location']}%")
            
            if filters.get('status') and filters['status'] != 'All':
                where_conditions.append("r.status = ?")
                params.append(filters['status'])
            
            if filters.get('source_type') and filters['source_type'] != 'All':
                where_conditions.append("r.source_type = ?")
                params.append(filters['source_type'])
        
        if where_conditions:
            query += " WHERE " + " AND ".join(where_conditions)
        
        query += " ORDER BY r.created_at DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        # Convert datetime strings to datetime objects
        if not df.empty and 'created_at' in df.columns:
            df['created_at'] = pd.to_datetime(df['created_at'])
            df['date'] = df['created_at'].dt.date
            df['hour'] = df['created_at'].dt.hour
            df['day_of_week'] = df['created_at'].dt.day_name()
        
        return df
        
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
        return pd.DataFrame()

def get_analytics_summary(df: pd.DataFrame) -> Dict:
    """Calculate summary statistics"""
    if df.empty:
        return {}
    
    summary = {
        'total_reports': len(df),
        'unique_locations': df['location'].nunique(),
        'unique_reporters': df['reporter_name'].nunique(),
        'avg_upvotes': df['upvotes'].mean() if 'upvotes' in df.columns else 0,
        'reports_with_advice': len(df[df['advice'].notna() & (df['advice'] != '')]),
        'verified_reports': len(df[df['status'] == 'verified']),
        'pending_reports': len(df[df['status'] == 'pending']),
        'resolved_reports': len(df[df['status'] == 'resolved']),
        'false_reports': len(df[df['status'] == 'false'])
    }
    
    return summary

def create_risk_type_chart(df: pd.DataFrame) -> go.Figure:
    """Create bar chart for risk types"""
    if df.empty:
        return go.Figure()
    
    risk_counts = df['risk_type'].value_counts()
    
    fig = go.Figure(data=[
        go.Bar(
            x=risk_counts.index,
            y=risk_counts.values,
            marker_color=['#dc3545', '#007bff', '#6f42c1', '#fd7e14', '#ffc107', '#6c757d'],
            text=risk_counts.values,
            textposition='auto'
        )
    ])
    
    fig.update_layout(
        title="Reports by Risk Type",
        xaxis_title="Risk Type",
        yaxis_title="Number of Reports",
        template="plotly_white",
        height=400
    )
    
    return fig

def create_status_pie_chart(df: pd.DataFrame) -> go.Figure:
    """Create pie chart for report status"""
    if df.empty:
        return go.Figure()
    
    status_counts = df['status'].value_counts()
    
    fig = go.Figure(data=[
        go.Pie(
            labels=status_counts.index,
            values=status_counts.values,
            hole=0.4,
            marker_colors=['#28a745', '#ffc107', '#007bff', '#dc3545']
        )
    ])
    
    fig.update_layout(
        title="Reports by Status",
        template="plotly_white",
        height=400
    )
    
    return fig

def create_time_series_chart(df: pd.DataFrame) -> go.Figure:
    """Create time series chart for reports over time"""
    if df.empty:
        return go.Figure()
    
    # Group by date and count reports
    daily_counts = df.groupby('date').size().reset_index(name='count')
    
    fig = go.Figure(data=[
        go.Scatter(
            x=daily_counts['date'],
            y=daily_counts['count'],
            mode='lines+markers',
            line=dict(color='#1f77b4', width=3),
            marker=dict(size=8)
        )
    ])
    
    fig.update_layout(
        title="Reports Over Time",
        xaxis_title="Date",
        yaxis_title="Number of Reports",
        template="plotly_white",
        height=400
    )
    
    return fig

def create_location_heatmap(df: pd.DataFrame) -> go.Figure:
    """Create heatmap for reports by location and risk type"""
    if df.empty:
        return go.Figure()
    
    # Create pivot table
    location_risk = df.groupby(['location', 'risk_type']).size().unstack(fill_value=0)
    
    fig = go.Figure(data=go.Heatmap(
        z=location_risk.values,
        x=location_risk.columns,
        y=location_risk.index,
        colorscale='Reds',
        text=location_risk.values,
        texttemplate="%{text}",
        textfont={"size": 10}
    ))
    
    fig.update_layout(
        title="Reports by Location and Risk Type",
        xaxis_title="Risk Type",
        yaxis_title="Location",
        template="plotly_white",
        height=500
    )
    
    return fig

def create_hourly_distribution_chart(df: pd.DataFrame) -> go.Figure:
    """Create chart showing report distribution by hour"""
    if df.empty:
        return go.Figure()
    
    hourly_counts = df['hour'].value_counts().sort_index()
    
    fig = go.Figure(data=[
        go.Bar(
            x=hourly_counts.index,
            y=hourly_counts.values,
            marker_color='#17a2b8',
            text=hourly_counts.values,
            textposition='auto'
        )
    ])
    
    fig.update_layout(
        title="Reports by Hour of Day",
        xaxis_title="Hour",
        yaxis_title="Number of Reports",
        template="plotly_white",
        height=400
    )
    
    return fig

def export_to_csv(df: pd.DataFrame) -> str:
    """Export data to CSV and return base64 encoded string"""
    try:
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_string = csv_buffer.getvalue()
        
        # Encode to base64
        b64 = base64.b64encode(csv_string.encode()).decode()
        return b64
    except Exception as e:
        st.error(f"Error exporting to CSV: {str(e)}")
        return ""

def display_filters() -> Dict:
    """Display filter controls and return filter dictionary"""
    st.markdown("### 🔍 Filters")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        date_from = st.date_input(
            "From Date",
            value=(datetime.now() - timedelta(days=30)).date(),
            key="date_from"
        )
        
        risk_type_filter = st.selectbox(
            "Risk Type",
            ["All"] + ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"],
            key="risk_type_filter"
        )
    
    with col2:
        date_to = st.date_input(
            "To Date",
            value=datetime.now().date(),
            key="date_to"
        )
        
        status_filter = st.selectbox(
            "Status",
            ["All", "pending", "verified", "resolved", "false"],
            key="status_filter"
        )
    
    with col3:
        location_filter = st.text_input(
            "Location (contains)",
            key="location_filter"
        )
        
        source_type_filter = st.selectbox(
            "Source Type",
            ["All", "user", "news", "social_media"],
            key="source_type_filter"
        )
    
    filters = {
        'date_from': date_from.strftime('%Y-%m-%d') if date_from else None,
        'date_to': date_to.strftime('%Y-%m-%d') if date_to else None,
        'risk_type': risk_type_filter,
        'status': status_filter,
        'location': location_filter,
        'source_type': source_type_filter
    }
    
    return filters

def display_summary_metrics(summary: Dict):
    """Display summary metrics in cards"""
    st.markdown("### 📊 Summary Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.get('total_reports', 0)}</div>
            <div class="metric-label">Total Reports</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.get('verified_reports', 0)}</div>
            <div class="metric-label">Verified Reports</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.get('unique_locations', 0)}</div>
            <div class="metric-label">Unique Locations</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.get('reports_with_advice', 0)}</div>
            <div class="metric-label">Reports with AI Advice</div>
        </div>
        """, unsafe_allow_html=True)

def display_charts(df: pd.DataFrame):
    """Display all charts"""
    st.markdown("### 📈 Analytics Charts")
    
    # Risk Type Chart
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Risk Type Distribution")
        fig_risk = create_risk_type_chart(df)
        st.plotly_chart(fig_risk, use_container_width=True)
    
    with col2:
        st.markdown("#### Report Status Distribution")
        fig_status = create_status_pie_chart(df)
        st.plotly_chart(fig_status, use_container_width=True)
    
    # Time Series Chart
    st.markdown("#### Reports Over Time")
    fig_time = create_time_series_chart(df)
    st.plotly_chart(fig_time, use_container_width=True)
    
    # Location Heatmap
    st.markdown("#### Location and Risk Type Heatmap")
    fig_heatmap = create_location_heatmap(df)
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # Hourly Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Hourly Distribution")
        fig_hourly = create_hourly_distribution_chart(df)
        st.plotly_chart(fig_hourly, use_container_width=True)
    
    with col2:
        st.markdown("#### Data Table Preview")
        if not df.empty:
            st.dataframe(
                df[['risk_type', 'location', 'status', 'created_at', 'upvotes']].head(10),
                use_container_width=True
            )

def display_export_section(df: pd.DataFrame):
    """Display export functionality"""
    st.markdown("### 📤 Export Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📊 Export to CSV", key="export_csv"):
            if not df.empty:
                csv_b64 = export_to_csv(df)
                if csv_b64:
                    st.success("✅ CSV exported successfully!")
                    st.download_button(
                        label="📥 Download CSV",
                        data=base64.b64decode(csv_b64),
                        file_name=f"road_risk_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.warning("No data to export")
    
    with col2:
        if st.button("📋 Show Raw Data", key="show_raw"):
            if not df.empty:
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("No data available")

def main():
    """Main function for the Analytics Dashboard"""
    st.set_page_config(
        page_title="Analytics Dashboard",
        page_icon="📊",
        layout="wide"
    )
    
    st.markdown(ANALYTICS_CSS, unsafe_allow_html=True)
    
    st.markdown("# 📊 Analytics Dashboard")
    st.markdown("Comprehensive analytics and insights for road risk reports")
    
    # Display filters
    filters = display_filters()
    
    # Load data
    with st.spinner("Loading data..."):
        df = get_reports_data(filters)
    
    if not df.empty:
        # Display summary metrics
        summary = get_analytics_summary(df)
        display_summary_metrics(summary)
        
        # Display charts
        display_charts(df)
        
        # Display export section
        display_export_section(df)
        
        # Show data insights
        st.markdown("### 💡 Insights")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if 'risk_type' in df.columns:
                most_common_risk = df['risk_type'].mode().iloc[0] if not df['risk_type'].mode().empty else "N/A"
                st.info(f"**Most Common Risk Type**: {most_common_risk}")
            
            if 'location' in df.columns:
                most_common_location = df['location'].mode().iloc[0] if not df['location'].mode().empty else "N/A"
                st.info(f"**Most Reported Location**: {most_common_location}")
        
        with col2:
            if 'created_at' in df.columns:
                recent_reports = len(df[df['created_at'] >= datetime.now() - timedelta(days=7)])
                st.success(f"**Reports in Last 7 Days**: {recent_reports}")
            
            if 'upvotes' in df.columns:
                avg_upvotes = df['upvotes'].mean()
                st.success(f"**Average Upvotes**: {avg_upvotes:.1f}")
    
    else:
        st.warning("No data found for the selected filters. Try adjusting your filter criteria.")

if __name__ == "__main__":
    main() 