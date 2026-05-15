
import streamlit as st
import pandas as pd

from sniffer import captured_packets, start_sniffing

# ---------------- PAGE SETTINGS ---------------- #

st.set_page_config(
    page_title="CyberShield Network Threat Monitor",
    layout="wide"
)

# ---------------- TITLE ---------------- #

st.title("🛡 CyberShield Network Threat Monitor")

st.markdown("### Real-Time Cybersecurity Traffic Monitoring Dashboard")

# ---------------- SIDEBAR ---------------- #

st.sidebar.title("🛡 Security Controls")
protocol_filter = st.sidebar.selectbox(
    "Filter Protocol",
    ["All", "TCP", "UDP", "ICMP"]
)

# ---------------- START BUTTON ---------------- #

if st.button("Start Packet Capture"):

    captured_packets.clear()

    start_sniffing()

# ---------------- DISPLAY DATA ---------------- #

if captured_packets:

    df = pd.DataFrame(captured_packets)

    # ------------ FILTERING ------------ #

    if protocol_filter != "All":
        df = df[df["Protocol"] == protocol_filter]

    # ------------ METRICS ------------ #

    tcp_count = len(df[df["Protocol"] == "TCP"])
    udp_count = len(df[df["Protocol"] == "UDP"])
    icmp_count = len(df[df["Protocol"] == "ICMP"])

    suspicious_count = len(
        df[df["Threat Level"] != "Safe"]
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Packets", len(df))
    col2.metric("TCP Packets", tcp_count)
    col3.metric("UDP Packets", udp_count)
    col4.metric("Suspicious Packets", suspicious_count)

    # ------------ ALERTS ------------ #

    if suspicious_count > 0:
        st.warning("Suspicious Traffic Detected!")

    # ------------ COLOR FUNCTION ------------ #

    def highlight_threat(val):

        if "High Risk" in str(val):
            return "background-color: red; color: white"

        elif "Medium Risk" in str(val):
            return "background-color: orange; color: black"

        elif "Safe" in str(val):
            return "background-color: green; color: white"

        return ""

    # ------------ PACKET TABLE ------------ #

    st.subheader("Captured Packets")

    styled_df = df.style.map(
        highlight_threat,
        subset=["Threat Level"]
    )

    st.dataframe(
    styled_df,
    width="stretch"
)

    # ------------ TRAFFIC GRAPH ------------ #

    st.subheader("Protocol Distribution")

    protocol_counts = df["Protocol"].value_counts()

    st.bar_chart(protocol_counts)

    # ------------ TOP SOURCE IPS ------------ #

    st.subheader("Top Source IP Addresses")

    top_ips = df["Source IP"].value_counts().head(5)

    st.bar_chart(top_ips)

    # ------------ DOWNLOAD REPORT ------------ #

    csv = df.to_csv(index=False)

    st.download_button(
        label="Download Packet Report",
        data=csv,
        file_name="packet_report.csv",
        mime="text/csv"
    )

else:

    st.info(
        "Click 'Start Packet Capture' to begin monitoring network traffic."
    )
st.markdown("---")
st.markdown(
    "Developed by Nishitha Sree | Cybersecurity Internship Project"
)