#!/usr/bin/env python3
"""
AI Safety Advice Engine for Nigerian Road Risk Reporter
Lightweight, rule-based safety advice generation for road risk reports
Python 3.13 compatible - No heavy dependencies
"""

import streamlit as st
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Optional

# Simple rule-based advice mapping
RISK_ADVICE_RULES = {
    "Robbery": {
        "high_risk_locations": ["Jos", "Kaduna", "Abuja", "Lagos", "Port Harcourt"],
        "advice": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
        "emergency_contacts": ["Police: 112", "Emergency: 0800-112-1199"]
    },
    "Flooding": {
        "high_risk_locations": ["Lagos", "Port Harcourt", "Calabar", "Warri"],
        "advice": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
        "emergency_contacts": ["Emergency: 0800-112-1199", "Road Safety: 0800-112-1199"]
    },
    "Protest": {
        "high_risk_locations": ["Lagos", "Abuja", "Kano", "Kaduna"],
        "advice": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
        "emergency_contacts": ["Police: 112", "Traffic Control: 0800-112-1199"]
    },
    "Road Damage": {
        "high_risk_locations": ["All"],
        "advice": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
        "emergency_contacts": ["Road Maintenance: 0800-112-1199", "Emergency: 0800-112-1199"]
    },
    "Traffic": {
        "high_risk_locations": ["Lagos", "Abuja", "Port Harcourt", "Kano"],
        "advice": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible.",
        "emergency_contacts": ["Traffic Control: 0800-112-1199"]
    },
    "Other": {
        "advice": "⚠️ **Road Incident**: Exercise caution in this area. Follow local traffic advisories and authorities.",
        "emergency_contacts": ["Emergency: 0800-112-1199", "Police: 112"]
    }
}

def get_time_context() -> Dict[str, str]:
    """Get current time context for advice generation"""
    now = datetime.now()
    hour = now.hour
    
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
    
    return context

def analyze_location_risk(location: str, risk_type: str) -> Dict[str, any]:
    """Analyze location-specific risk factors"""
    location_lower = location.lower()
    time_context = get_time_context()
    
    risk_analysis = {
        "is_high_risk_location": False,
        "time_context": time_context,
        "additional_warnings": []
    }
    
    # Check if location is in high-risk list
    if risk_type in RISK_ADVICE_RULES:
        high_risk_locations = RISK_ADVICE_RULES[risk_type].get("high_risk_locations", [])
        for high_risk_loc in high_risk_locations:
            if high_risk_loc.lower() in location_lower:
                risk_analysis["is_high_risk_location"] = True
                break
    
    # Add time-based warnings
    if time_context["time_of_day"] == "night" and risk_type == "Robbery":
        risk_analysis["additional_warnings"].append("⚠️ **Night Travel Warning**: This area is particularly dangerous at night.")
    
    if time_context["traffic_period"] == "rush_hour" and risk_type == "Traffic":
        risk_analysis["additional_warnings"].append("🚗 **Rush Hour**: Expect heavy traffic congestion.")
    
    return risk_analysis

def generate_safety_advice(risk_type: str, location: str, description: str = "") -> Dict[str, any]:
    """Generate comprehensive safety advice based on risk type and location"""
    try:
        # Get base advice for risk type
        base_advice = RISK_ADVICE_RULES.get(risk_type, RISK_ADVICE_RULES["Other"])
        
        # Analyze location-specific risks
        risk_analysis = analyze_location_risk(location, risk_type)
        
        # Build comprehensive advice
        advice_parts = [base_advice["advice"]]
        
        # Add additional warnings
        for warning in risk_analysis["additional_warnings"]:
            advice_parts.append(warning)
        
        # Add location-specific advice
        if risk_analysis["is_high_risk_location"]:
            advice_parts.append("📍 **High-Risk Area**: This location has been flagged as high-risk. Exercise extreme caution.")
        
        # Combine all advice
        full_advice = "\n\n".join(advice_parts)
        
        # Determine risk level
        risk_level = "high" if risk_analysis["is_high_risk_location"] else "medium"
        if risk_type == "Robbery" and risk_analysis["time_context"]["time_of_day"] == "night":
            risk_level = "critical"
        
        advice_data = {
            "advice": full_advice,
            "risk_level": risk_level,
            "emergency_contacts": base_advice.get("emergency_contacts", []),
            "generated_at": datetime.now().isoformat(),
            "risk_analysis": risk_analysis
        }
        
        return advice_data
        
    except Exception as e:
        # Fallback advice
        return {
            "advice": "⚠️ **General Warning**: Exercise caution in this area. Follow local traffic advisories.",
            "risk_level": "medium",
            "emergency_contacts": ["Emergency: 0800-112-1199"],
            "generated_at": datetime.now().isoformat(),
            "risk_analysis": {"is_high_risk_location": False, "time_context": get_time_context(), "additional_warnings": []}
        }

def save_advice_to_database(report_id: int, advice_data: Dict[str, any]) -> bool:
    """Save generated advice to database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Update the risk_reports table with advice and risk_level
        cursor.execute('''
            UPDATE risk_reports 
            SET advice = ?, risk_level = ?
            WHERE id = ?
        ''', (
            advice_data["advice"],
            advice_data["risk_level"],
            report_id
        ))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        st.error(f"Failed to save advice to database: {str(e)}")
        return False

def get_advice_for_report(report_id: int) -> Optional[Dict[str, any]]:
    """Retrieve advice for a specific report"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT advice, risk_level, created_at
            FROM risk_reports
            WHERE id = ?
        ''', (report_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            return {
                "advice": result[0],
                "risk_level": result[1] or "medium",
                "created_at": result[2]
            }
        
        return None
        
    except Exception as e:
        st.error(f"Failed to retrieve advice: {str(e)}")
        return None

def generate_advice_with_delay(risk_type: str, location: str, report_id: int) -> Dict[str, any]:
    """Generate advice with 2-second delay to simulate AI processing"""
    try:
        # Show loading message
        with st.spinner("🤖 AI is analyzing the risk and generating safety advice..."):
            time.sleep(2)  # Simulate AI processing time
        
        # Generate advice
        advice_data = generate_safety_advice(risk_type, location)
        
        # Save to database
        if save_advice_to_database(report_id, advice_data):
            return advice_data
        else:
            return {"error": "Failed to save advice to database"}
            
    except Exception as e:
        return {"error": f"Failed to generate advice: {str(e)}"}

def display_advice_interface():
    """Display the AI advice interface"""
    st.markdown("## 🤖 AI Safety Advice Engine")
    st.markdown("Generate intelligent safety advice for road risk reports.")
    
    # Manual advice generation
    with st.expander("🔧 Manual Advice Generation", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            risk_type = st.selectbox(
                "Risk Type",
                ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
            )
        
        with col2:
            location = st.text_input("Location", placeholder="e.g., Lagos, Abuja, Kaduna")
        
        if st.button("Generate Advice"):
            if location:
                advice_data = generate_safety_advice(risk_type, location)
                
                st.markdown("### Generated Advice")
                st.markdown(advice_data["advice"])
                
                st.markdown(f"**Risk Level:** {advice_data['risk_level'].upper()}")
                
                if advice_data.get("emergency_contacts"):
                    st.markdown("**Emergency Contacts:**")
                    for contact in advice_data["emergency_contacts"]:
                        st.markdown(f"- {contact}")
            else:
                st.error("Please enter a location.")
    
    # View recent advice
    with st.expander("📋 Recent Advice", expanded=False):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, risk_type, location, advice, risk_level, created_at
                FROM risk_reports
                WHERE advice IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 10
            ''')
            
            recent_advice = cursor.fetchall()
            conn.close()
            
            if recent_advice:
                for report in recent_advice:
                    with st.container():
                        st.markdown(f"**Report #{report[0]}** - {report[1]} at {report[2]}")
                        st.markdown(f"**Risk Level:** {report[4]}")
                        st.markdown(report[3])
                        st.markdown(f"*Generated: {report[5]}*")
                        st.divider()
            else:
                st.info("No advice has been generated yet.")
                
        except Exception as e:
            st.error(f"Failed to load recent advice: {str(e)}")

def main():
    """Main function for standalone AI advice module"""
    st.set_page_config(
        page_title="AI Safety Advice Engine",
        page_icon="🤖",
        layout="wide"
    )
    
    st.title("🤖 AI Safety Advice Engine")
    st.markdown("Generate intelligent safety advice for road risk reports.")
    
    display_advice_interface()

if __name__ == "__main__":
    main() 