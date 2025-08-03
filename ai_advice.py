#!/usr/bin/env python3
"""
AI Safety Advice Engine for Nigerian Road Risk Reporter
Rule-based safety advice generation for road risk reports
"""

import streamlit as st
import sqlite3
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

# Risk type to advice mapping
RISK_ADVICE_RULES = {
    "Robbery": {
        "high_risk_locations": ["Jos", "Kaduna", "Abuja", "Lagos", "Port Harcourt"],
        "time_based_rules": {
            "night": "Avoid this route after 6PM. Use alternative highways and travel in groups if possible.",
            "day": "Exercise extreme caution. Travel with others and avoid isolated areas."
        },
        "general_advice": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
        "emergency_contacts": ["Police: 112", "Emergency: 0800-112-1199"]
    },
    "Flooding": {
        "high_risk_locations": ["Lagos", "Port Harcourt", "Calabar", "Warri"],
        "seasonal_rules": {
            "rainy_season": "Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
            "dry_season": "Check road conditions before travel. Some areas may still have water damage."
        },
        "general_advice": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
        "emergency_contacts": ["Emergency: 0800-112-1199", "Road Safety: 0800-112-1199"]
    },
    "Protest": {
        "high_risk_locations": ["Lagos", "Abuja", "Kano", "Kaduna"],
        "time_based_rules": {
            "weekend": "Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
            "weekday": "Monitor local news for updates. Consider postponing non-essential travel."
        },
        "general_advice": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
        "emergency_contacts": ["Police: 112", "Traffic Control: 0800-112-1199"]
    },
    "Road Damage": {
        "high_risk_locations": ["All"],
        "severity_rules": {
            "severe": "Major road damage detected. Use alternative routes. Report to authorities immediately.",
            "moderate": "Road damage present. Drive carefully and report to authorities.",
            "minor": "Minor road damage. Exercise caution and report to authorities."
        },
        "general_advice": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
        "emergency_contacts": ["Road Maintenance: 0800-112-1199", "Emergency: 0800-112-1199"]
    },
    "Traffic": {
        "high_risk_locations": ["Lagos", "Abuja", "Port Harcourt", "Kano"],
        "time_based_rules": {
            "rush_hour": "Heavy traffic congestion during peak hours. Consider alternative routes or delay travel.",
            "off_peak": "Moderate traffic. Plan your route accordingly."
        },
        "general_advice": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible.",
        "emergency_contacts": ["Traffic Control: 0800-112-1199"]
    },
    "Other": {
        "general_advice": "⚠️ **Road Incident**: Exercise caution in this area. Follow local traffic advisories and authorities.",
        "emergency_contacts": ["Emergency: 0800-112-1199", "Police: 112"]
    }
}

def get_current_time_context() -> Dict[str, str]:
    """Get current time context for advice generation"""
    now = datetime.now()
    hour = now.hour
    month = now.month
    
    context = {}
    
    # Time of day
    if 6 <= hour < 18:
        context["time_of_day"] = "day"
    else:
        context["time_of_day"] = "night"
    
    # Rush hour detection
    if (7 <= hour <= 9) or (17 <= hour <= 19):
        context["traffic_period"] = "rush_hour"
    else:
        context["traffic_period"] = "off_peak"
    
    # Weekend detection
    if now.weekday() >= 5:  # Saturday = 5, Sunday = 6
        context["day_type"] = "weekend"
    else:
        context["day_type"] = "weekday"
    
    # Rainy season detection (April to October in Nigeria)
    if 4 <= month <= 10:
        context["season"] = "rainy_season"
    else:
        context["season"] = "dry_season"
    
    return context

def analyze_location_risk(location: str, risk_type: str) -> Dict[str, any]:
    """Analyze location-specific risk factors"""
    location_lower = location.lower()
    
    # Check if location is in high-risk areas for the risk type
    high_risk_locations = RISK_ADVICE_RULES.get(risk_type, {}).get("high_risk_locations", [])
    is_high_risk_location = any(risk_loc.lower() in location_lower for risk_loc in high_risk_locations)
    
    # Determine severity based on location and risk type
    severity = "moderate"
    if is_high_risk_location:
        severity = "severe"
    elif risk_type in ["Robbery", "Flooding"]:
        severity = "high"
    
    return {
        "is_high_risk_location": is_high_risk_location,
        "severity": severity,
        "location_analysis": f"Location '{location}' is {'high-risk' if is_high_risk_location else 'moderate-risk'} for {risk_type}"
    }

def generate_safety_advice(risk_type: str, location: str, description: str = "") -> Dict[str, any]:
    """
    Generate comprehensive safety advice based on risk type, location, and context
    """
    try:
        # Get current time context
        context = get_current_time_context()
        
        # Analyze location risk
        location_analysis = analyze_location_risk(location, risk_type)
        
        # Get base advice rules for this risk type
        risk_rules = RISK_ADVICE_RULES.get(risk_type, RISK_ADVICE_RULES["Other"])
        
        # Generate primary advice
        primary_advice = risk_rules.get("general_advice", "⚠️ Exercise caution in this area.")
        
        # Generate contextual advice based on time and location
        contextual_advice = []
        
        # Time-based advice
        if risk_type == "Robbery" and context["time_of_day"] == "night":
            contextual_advice.append(risk_rules.get("time_based_rules", {}).get("night", ""))
        elif risk_type == "Traffic" and context["traffic_period"] == "rush_hour":
            contextual_advice.append(risk_rules.get("time_based_rules", {}).get("rush_hour", ""))
        elif risk_type == "Protest" and context["day_type"] == "weekend":
            contextual_advice.append(risk_rules.get("time_based_rules", {}).get("weekend", ""))
        
        # Seasonal advice for flooding
        if risk_type == "Flooding":
            seasonal_advice = risk_rules.get("seasonal_rules", {}).get(context["season"], "")
            if seasonal_advice:
                contextual_advice.append(seasonal_advice)
        
        # Severity-based advice for road damage
        if risk_type == "Road Damage":
            severity_advice = risk_rules.get("severity_rules", {}).get(location_analysis["severity"], "")
            if severity_advice:
                contextual_advice.append(severity_advice)
        
        # Location-specific advice
        if location_analysis["is_high_risk_location"]:
            contextual_advice.append(f"⚠️ **High-Risk Area**: {location} is known for {risk_type} incidents. Exercise extreme caution.")
        
        # Combine all advice
        full_advice = primary_advice
        if contextual_advice:
            full_advice += "\n\n" + "\n\n".join(contextual_advice)
        
        # Add emergency contacts
        emergency_contacts = risk_rules.get("emergency_contacts", ["Emergency: 0800-112-1199"])
        contacts_text = "\n\n📞 **Emergency Contacts**:\n" + "\n".join([f"• {contact}" for contact in emergency_contacts])
        full_advice += contacts_text
        
        # Add timestamp and context
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        context_info = f"\n\n📅 **Generated**: {timestamp}"
        full_advice += context_info
        
        return {
            "success": True,
            "advice": full_advice,
            "risk_level": location_analysis["severity"],
            "context": context,
            "location_analysis": location_analysis,
            "timestamp": timestamp,
            "risk_type": risk_type,
            "location": location
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error generating advice: {str(e)}",
            "advice": "⚠️ **Safety Notice**: Exercise caution in this area. Contact local authorities for current conditions.",
            "risk_level": "unknown",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def save_advice_to_database(report_id: int, advice_data: Dict[str, any]) -> bool:
    """Save generated advice to the risk_reports database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Add advice column if it doesn't exist
        cursor.execute("PRAGMA table_info(risk_reports)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'advice' not in columns:
            cursor.execute('ALTER TABLE risk_reports ADD COLUMN advice TEXT')
            cursor.execute('ALTER TABLE risk_reports ADD COLUMN advice_generated_at TIMESTAMP')
            cursor.execute('ALTER TABLE risk_reports ADD COLUMN risk_level TEXT')
        
        # Update the report with advice
        cursor.execute('''
            UPDATE risk_reports 
            SET advice = ?, advice_generated_at = ?, risk_level = ?
            WHERE id = ?
        ''', (
            advice_data.get("advice", ""),
            advice_data.get("timestamp", ""),
            advice_data.get("risk_level", "unknown"),
            report_id
        ))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        st.error(f"Error saving advice to database: {str(e)}")
        return False

def get_advice_for_report(report_id: int) -> Optional[Dict[str, any]]:
    """Retrieve advice for a specific report"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT advice, advice_generated_at, risk_level
            FROM risk_reports 
            WHERE id = ?
        ''', (report_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                "advice": result[0],
                "generated_at": result[1],
                "risk_level": result[2]
            }
        return None
        
    except Exception as e:
        st.error(f"Error retrieving advice: {str(e)}")
        return None

def display_advice_interface():
    """Display the AI advice interface in Streamlit"""
    st.markdown("## 🤖 AI Safety Advice Engine")
    st.markdown("Generate intelligent safety advice for road risk reports")
    
    # Test advice generation
    with st.expander("🧪 Test Advice Generation", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            test_risk_type = st.selectbox(
                "Risk Type",
                ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"],
                key="test_risk_type"
            )
            test_location = st.text_input("Location", "Lagos", key="test_location")
            test_description = st.text_area("Description (optional)", key="test_description")
        
        with col2:
            if st.button("Generate Test Advice", key="test_generate"):
                with st.spinner("Generating AI safety advice..."):
                    # Simulate processing delay
                    time.sleep(2)
                    
                    advice_data = generate_safety_advice(test_risk_type, test_location, test_description)
                    
                    if advice_data["success"]:
                        st.success("✅ Advice generated successfully!")
                        
                        # Display advice
                        st.markdown("### Generated Advice:")
                        st.markdown(advice_data["advice"])
                        
                        # Display context
                        with st.expander("📊 Analysis Details"):
                            st.json(advice_data)
                    else:
                        st.error(f"❌ Error: {advice_data['error']}")
    
    # Show advice statistics
    with st.expander("📈 Advice Statistics", expanded=False):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            # Get advice statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_reports,
                    COUNT(advice) as reports_with_advice,
                    risk_level,
                    COUNT(*) as count
                FROM risk_reports 
                GROUP BY risk_level
            ''')
            
            stats = cursor.fetchall()
            conn.close()
            
            if stats:
                st.markdown("### Advice Coverage")
                total_reports = sum(row[3] for row in stats)
                reports_with_advice = sum(row[3] for row in stats if row[2] is not None)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Reports", total_reports)
                with col2:
                    st.metric("Reports with Advice", reports_with_advice)
                with col3:
                    coverage = (reports_with_advice / total_reports * 100) if total_reports > 0 else 0
                    st.metric("Coverage %", f"{coverage:.1f}%")
                
                # Risk level distribution
                st.markdown("### Risk Level Distribution")
                risk_levels = [row[2] for row in stats if row[2] is not None]
                if risk_levels:
                    risk_counts = {}
                    for level in risk_levels:
                        risk_counts[level] = risk_counts.get(level, 0) + 1
                    
                    for level, count in risk_counts.items():
                        st.write(f"• **{level.title()}**: {count} reports")
            
        except Exception as e:
            st.error(f"Error loading statistics: {str(e)}")

def main():
    """Main function for the AI Advice Engine"""
    st.set_page_config(
        page_title="AI Safety Advice Engine",
        page_icon="🤖",
        layout="wide"
    )
    
    st.markdown("""
    <style>
    .advice-box {
        background-color: #f0f8ff;
        border-left: 4px solid #1f77b4;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .high-risk { border-left-color: #dc3545; background-color: #fff5f5; }
    .moderate-risk { border-left-color: #ffc107; background-color: #fffbf0; }
    .low-risk { border-left-color: #28a745; background-color: #f0fff4; }
    </style>
    """, unsafe_allow_html=True)
    
    display_advice_interface()

if __name__ == "__main__":
    main() 