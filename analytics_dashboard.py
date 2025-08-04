#!/usr/bin/env python3
"""
Analytics Dashboard for Nigerian Road Risk Reporter
Lightweight, interactive charts and export functionality
Python 3.13 compatible - Streamlit Cloud ready
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import io
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
        
        return df
        
    except Exception as e:
        st.error(f"Failed to load data: {str(e)}")
        return pd.DataFrame()

def get_analytics_summary(df: pd.DataFrame) -> Dict:
    """Calculate summary metrics from the data"""
    if df.empty:
        return {
            'total_reports': 0,
            'reports_today': 0,
            'reports_this_week': 0,
            'avg_upvotes': 0,
            'top_risk_type': 'None',
            'top_location': 'None'
        }
    
    try:
        now = datetime.now()
        today = now.date()
        week_ago = today - timedelta(days=7)
        
        # Basic metrics
        total_reports = len(df)
        reports_today = len(df[df['date'] == today])
        reports_this_week = len(df[df['date'] >= week_ago])
        
        # Average upvotes
        avg_upvotes = df['upvotes'].mean() if 'upvotes' in df.columns else 0
        
        # Top risk type
        top_risk_type = df['risk_type'].mode().iloc[0] if not df['risk_type'].mode().empty else 'None'
        
        # Top location
        top_location = df['location'].mode().iloc[0] if not df['location'].mode().empty else 'None'
        
        return {
            'total_reports': total_reports,
            'reports_today': reports_today,
            'reports_this_week': reports_this_week,
            'avg_upvotes': round(avg_upvotes, 1),
            'top_risk_type': top_risk_type,
            'top_location': top_location
        }
        
    except Exception as e:
        st.error(f"Failed to calculate summary: {str(e)}")
        return {
            'total_reports': 0,
            'reports_today': 0,
            'reports_this_week': 0,
            'avg_upvotes': 0,
            'top_risk_type': 'Error',
            'top_location': 'Error'
        }

def create_risk_type_chart(df: pd.DataFrame) -> go.Figure:
    """Create risk type distribution chart"""
    if df.empty:
        # Return empty chart
        fig = go.Figure()
        fig.add_annotation(text="No data available", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    try:
        risk_counts = df['risk_type'].value_counts()
        
        fig = go.Figure(data=[
            go.Bar(
                x=risk_counts.index,
                y=risk_counts.values,
                marker_color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
            )
        ])
        
        fig.update_layout(
            title="Reports by Risk Type",
            xaxis_title="Risk Type",
            yaxis_title="Number of Reports",
            height=400
        )
        
        return fig
        
    except Exception as e:
        st.error(f"Failed to create risk type chart: {str(e)}")
        fig = go.Figure()
        fig.add_annotation(text="Chart error", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig

def create_status_pie_chart(df: pd.DataFrame) -> go.Figure:
    """Create status distribution pie chart"""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No data available", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    try:
        status_counts = df['status'].value_counts()
        
        fig = go.Figure(data=[
            go.Pie(
                labels=status_counts.index,
                values=status_counts.values,
                hole=0.3
            )
        ])
        
        fig.update_layout(
            title="Reports by Status",
            height=400
        )
        
        return fig
        
    except Exception as e:
        st.error(f"Failed to create status chart: {str(e)}")
        fig = go.Figure()
        fig.add_annotation(text="Chart error", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig

def create_time_series_chart(df: pd.DataFrame) -> go.Figure:
    """Create time series chart of reports over time"""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No data available", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    try:
        # Group by date and count reports
        daily_counts = df.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure(data=[
            go.Scatter(
                x=daily_counts['date'],
                y=daily_counts['count'],
                mode='lines+markers',
                line=dict(color='#1f77b4', width=2),
                marker=dict(size=6)
            )
        ])
        
        fig.update_layout(
            title="Reports Over Time",
            xaxis_title="Date",
            yaxis_title="Number of Reports",
            height=400
        )
        
        return fig
        
    except Exception as e:
        st.error(f"Failed to create time series chart: {str(e)}")
        fig = go.Figure()
        fig.add_annotation(text="Chart error", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig

def create_hourly_distribution_chart(df: pd.DataFrame) -> go.Figure:
    """Create hourly distribution chart"""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No data available", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    try:
        hourly_counts = df['hour'].value_counts().sort_index()
        
        fig = go.Figure(data=[
            go.Bar(
                x=hourly_counts.index,
                y=hourly_counts.values,
                marker_color='#ff7f0e'
            )
        ])
        
        fig.update_layout(
            title="Reports by Hour of Day",
            xaxis_title="Hour",
            yaxis_title="Number of Reports",
            height=400
        )
        
        return fig
        
    except Exception as e:
        st.error(f"Failed to create hourly chart: {str(e)}")
        fig = go.Figure()
        fig.add_annotation(text="Chart error", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig

def export_to_csv(df: pd.DataFrame) -> str:
    """Export data to CSV format"""
    try:
        if df.empty:
            return ""
        
        # Prepare data for export
        export_df = df.copy()
        
        # Convert datetime to string for CSV
        if 'created_at' in export_df.columns:
            export_df['created_at'] = export_df['created_at'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Remove date and hour columns (they were added for analysis)
        if 'date' in export_df.columns:
            export_df = export_df.drop('date', axis=1)
        if 'hour' in export_df.columns:
            export_df = export_df.drop('hour', axis=1)
        
        # Convert to CSV
        csv = export_df.to_csv(index=False)
        return csv
        
    except Exception as e:
        st.error(f"Failed to export data: {str(e)}")
        return ""

def display_filters() -> Dict:
    """Display filter controls and return filter dictionary"""
    st.markdown("### 📊 Filters")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        date_from = st.date_input(
            "From Date",
            value=datetime.now().date() - timedelta(days=30),
            max_value=datetime.now().date()
        )
        
        risk_type = st.selectbox(
            "Risk Type",
            ["All", "Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        )
    
    with col2:
        date_to = st.date_input(
            "To Date",
            value=datetime.now().date(),
            max_value=datetime.now().date()
        )
        
        status = st.selectbox(
            "Status",
            ["All", "pending", "verified", "resolved", "false"]
        )
    
    with col3:
        location = st.text_input("Location (contains)", placeholder="e.g., Lagos")
    
    return {
        'date_from': date_from.strftime('%Y-%m-%d') if date_from else None,
        'date_to': date_to.strftime('%Y-%m-%d') if date_to else None,
        'risk_type': risk_type,
        'status': status,
        'location': location if location else None
    }

def display_summary_metrics(summary: Dict):
    """Display summary metrics in cards"""
    st.markdown("### 📈 Summary Metrics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['total_reports']}</div>
            <div class="metric-label">Total Reports</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['reports_today']}</div>
            <div class="metric-label">Reports Today</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['reports_this_week']}</div>
            <div class="metric-label">Reports This Week</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['avg_upvotes']}</div>
            <div class="metric-label">Avg Upvotes</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['top_risk_type']}</div>
            <div class="metric-label">Top Risk Type</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['top_location']}</div>
            <div class="metric-label">Top Location</div>
        </div>
        """, unsafe_allow_html=True)

def display_charts(df: pd.DataFrame):
    """Display all charts"""
    st.markdown("### 📊 Charts")
    
    # Risk type distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(create_risk_type_chart(df), use_container_width=True)
    
    with col2:
        st.plotly_chart(create_status_pie_chart(df), use_container_width=True)
    
    # Time series and hourly distribution
    col3, col4 = st.columns(2)
    
    with col3:
        st.plotly_chart(create_time_series_chart(df), use_container_width=True)
    
    with col4:
        st.plotly_chart(create_hourly_distribution_chart(df), use_container_width=True)

def display_export_section(df: pd.DataFrame):
    """Display export functionality"""
    st.markdown("### 📥 Export Data")
    
    if not df.empty:
        csv_data = export_to_csv(df)
        
        if csv_data:
            st.download_button(
                label="📊 Download CSV",
                data=csv_data,
                file_name=f"road_risk_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            
            st.info(f"📊 Data ready for export: {len(df)} records")
        else:
            st.error("Failed to prepare data for export")
    else:
        st.warning("No data available for export")

def main():
    """Main function for analytics dashboard"""
    st.set_page_config(
        page_title="Analytics Dashboard",
        page_icon="📊",
        layout="wide"
    )
    
    st.title("📊 Analytics Dashboard")
    st.markdown("Comprehensive analytics and insights for road risk reports")
    
    # Apply custom CSS
    st.markdown(ANALYTICS_CSS, unsafe_allow_html=True)
    
    # Display filters
    filters = display_filters()
    
    # Load data
    df = get_reports_data(filters)
    
    # Display summary metrics
    summary = get_analytics_summary(df)
    display_summary_metrics(summary)
    
    # Display charts
    display_charts(df)
    
    # Display export section
    display_export_section(df)
    
    # Show raw data
    with st.expander("📋 Raw Data", expanded=False):
        if not df.empty:
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No data available")

if __name__ == "__main__":
    main() 