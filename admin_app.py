import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Road Status Admin", page_icon="🛠️", layout="wide")

def get_demo_reports():
    from streamlit_app_minimal import get_demo_data
    return pd.DataFrame(get_demo_data())

def main():
    st.title("🛠️ Road Status Admin Console")

    # Role selection (demo): admin, super_admin, ultimate_admin
    role = st.sidebar.selectbox("Role", ["admin", "super_admin", "ultimate_admin"])
    st.sidebar.caption("Roles map to agencies, states, and developers respectively.")

    # Auth placeholder (assumes already authenticated admins)
    st.sidebar.success(f"Role: {role}")

    df = get_demo_reports()

    tabs = st.tabs(["Reports", "Traffic / Activity", "Data Export"]) 

    with tabs[0]:
        st.subheader("Manage Reports")
        status_filter = st.multiselect("Filter by status", sorted(df.status.unique().tolist()), default=sorted(df.status.unique().tolist()))
        risk_filter = st.multiselect("Filter by risk", sorted(df.risk_level.unique().tolist()), default=sorted(df.risk_level.unique().tolist()))
        filtered = df[df.status.isin(status_filter) & df.risk_level.isin(risk_filter)]
        st.dataframe(filtered, use_container_width=True)

        st.markdown("### Edit Selected Report")
        selected_id = st.number_input("Report ID", min_value=1, max_value=int(df.id.max()), value=1)
        target = df[df.id == selected_id]
        if not target.empty:
            new_status = st.selectbox("Status", ["Pending", "Verified", "Resolved"], index=["Pending", "Verified", "Resolved"].index(target.iloc[0].status))
            new_risk = st.selectbox("Risk", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(target.iloc[0].risk_level))
            if st.button("Save Changes"):
                st.success(f"Report {selected_id} updated (demo).")
        else:
            st.info("Choose a valid Report ID.")

    with tabs[1]:
        st.subheader("Traffic and Activity Monitoring")
        st.caption("Demo metrics; integrate with real analytics in production.")
        col1, col2, col3 = st.columns(3)
        col1.metric("Active Users (24h)", 128)
        col2.metric("Reports Today", 17)
        col3.metric("Avg Time to Verify", "3h 12m")

    with tabs[2]:
        st.subheader("Download Reports")
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", csv, file_name=f"reports_{datetime.now().date()}.csv", mime="text/csv")

if __name__ == "__main__":
    main()


