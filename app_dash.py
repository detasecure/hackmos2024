# frontend/app.py
import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from datetime import timedelta

def show_dashboardv2():
    st.title("GETSecured ChainSentinel Dashboard")

    # Add tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "Overview",
        "Security Incidents",
        "Provider Analysis",
        "Active Monitoring"
    ])

    with tab1:
        show_overview_dashboard()

    with tab2:
        show_security_incidents()

    with tab3:
        show_bounty_analysis()

    with tab4:
        show_active_monitoring()


def show_security_incidents():
    st.header("Security Incident Monitoring Capabilities")

    # Create incident categories with detailed explanations
    incident_categories = {
        "Smart Contract Vulnerabilities": {
            "description": "Detection of vulnerabilities in smart contract code and execution",
            "incidents": [
                "Reentrancy Attacks",
                "Integer Overflow/Underflow",
                "Access Control Issues",
                "Logic Bugs",
                "Unchecked Return Values",
                "Front-Running Vulnerabilities"
            ],
            "severity": "Critical",
            "monitoring": "Real-time"
        },
        "Cross-Chain Security": {
            "description": "Monitoring of cross-chain transactions and bridge security",
            "incidents": [
                "Bridge Exploits",
                "IBC Protocol Violations",
                "Relay Attacks",
                "Cross-Chain Double Spending",
                "Bridge Fund Lockups"
            ],
            "severity": "Critical",
            "monitoring": "Real-time"
        },
        "DeFi Protocol Attacks": {
            "description": "Detection of attacks targeting DeFi protocols and mechanisms",
            "incidents": [
                "Flash Loan Attacks",
                "Price Manipulation",
                "MEV Exploitation",
                "Liquidity Pool Attacks",
                "Governance Attacks"
            ],
            "severity": "High",
            "monitoring": "Real-time"
        },
        "Network Level Threats": {
            "description": "Monitoring of network-level security issues",
            "incidents": [
                "Consensus Attacks",
                "Network Partitioning",
                "Node Attacks",
                "Validator Misbehavior",
                "Block Reorganizations"
            ],
            "severity": "Critical",
            "monitoring": "Real-time"
        }
    }

    # Display incidents in an expandable format
    for category, details in incident_categories.items():
        with st.expander(f"{category} ({details['severity']})"):
            st.write(f"**Description:** {details['description']}")
            st.write("**Monitored Incidents:**")
            for incident in details['incidents']:
                st.write(f"- {incident}")
            st.write(f"**Monitoring Type:** {details['monitoring']}")


def show_bounty_analysis():
    st.header("Provider Analysis")

    # Define bounty providers and their focus areas
    bounty_providers = {
        "Osmosis": {
            "focus": "DeFi & Smart Accounts",
            # "prize_pool": "$10,000",
            "relevant_issues": [
                "Smart Account Vulnerabilities",
                "DEX Protocol Security",
                "Liquidity Pool Safety",
                "Cross-Chain Trading Issues"
            ],
            "incidents_detected": 3,
            "status": "Active"
        },
        "Neutron": {
            "focus": "Smart Contract Security",
            # "prize_pool": "$15,000",
            "relevant_issues": [
                "Smart Contract Vulnerabilities",
                "ICTX/ICQ Security",
                "Oracle Data Integrity",
                "Contract Interaction Issues"
            ],
            "incidents_detected": 5,
            "status": "Active"
        },
        "Warden Protocol": {
            "focus": "AI Security",
            # "prize_pool": "$15,000",
            "relevant_issues": [
                "AI Model Security",
                "Automated Response Safety",
                "Decision Logic Vulnerabilities",
                "Data Integrity Issues"
            ],
            "incidents_detected": 2,
            "status": "Active"
        },
        "Interchain": {
            "focus": "Cross-Chain Security",
            # "prize_pool": "$30,000",
            "relevant_issues": [
                "IBC Protocol Violations",
                "Cross-Chain Attack Patterns",
                "Bridge Security Issues",
                "State Sync Problems"
            ],
            "incidents_detected": 4,
            "status": "Active"
        }
    }

    # Create and display the bounty analysis table
    bounty_df = pd.DataFrame.from_dict(bounty_providers, orient='index')

    # Add styling
    def color_status(val):
        if val == "Active":
            return 'background-color: lightgreen'
        return 'background-color: lightyellow'

    styled_df = bounty_df.style.applymap(
        color_status,
        subset=['status']
    )

    st.dataframe(styled_df)

    # Add detailed analysis for each provider
    for provider, details in bounty_providers.items():
        with st.expander(f"Detailed Analysis: {provider}"):
            col1, col2 = st.columns(2)

            with col1:
                st.write(f"**Focus Area:** {details['focus']}")
                # st.write(f"**Prize Pool:** {details['prize_pool']}")
                st.write(f"**Status:** {details['status']}")

            with col2:
                st.write("**Recent Issues:**")
                for issue in details['relevant_issues']:
                    st.write(f"- {issue}")

            # Add charts for issue distribution
            st.write("**Issue Distribution**")
            issue_data = {
                "Critical": 30,
                "High": 40,
                "Medium": 20,
                "Low": 10
            }
            st.bar_chart(issue_data)


def show_active_monitoring():
    st.header("Active Security Monitoring")

    # Real-time monitoring metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Chains Monitored", "5", "+1")
    with col2:
        st.metric("Active Threats", "3", "-2")
    with col3:
        st.metric("Response Time", "45s", "-5s")

    # Active monitoring status
    monitoring_status = {
        "Osmosis": {
            "status": "Active",
            "last_block": "8234567",
            "threats_detected": 2,
            "response_time": "43s"
        },
        "Cosmos Hub": {
            "status": "Active",
            "last_block": "12345678",
            "threats_detected": 1,
            "response_time": "38s"
        },
        "Neutron": {
            "status": "Active",
            "last_block": "3456789",
            "threats_detected": 0,
            "response_time": "41s"
        }
    }

    # Display monitoring status
    st.subheader("Chain Monitoring Status")
    status_df = pd.DataFrame.from_dict(monitoring_status, orient='index')

    # Add status indicators
    def color_monitor_status(val):
        if val == "Active":
            return 'background-color: lightgreen'
        return 'background-color: pink'

    styled_status_df = status_df.style.applymap(
        color_monitor_status,
        subset=['status']
    )

    st.dataframe(styled_status_df)

    # Add real-time threat feed
    st.subheader("Real-time Threat Feed")
    threat_feed = [
        {
            "timestamp": "2024-10-26 15:45:23",
            "chain": "Osmosis",
            "type": "Smart Contract Vulnerability",
            "severity": "High",
            "status": "Investigating"
        },
        {
            "timestamp": "2024-10-26 15:43:12",
            "chain": "Cosmos Hub",
            "type": "Bridge Security Issue",
            "severity": "Critical",
            "status": "Resolved"
        }
    ]

    threat_df = pd.DataFrame(threat_feed)
    st.dataframe(threat_df)

    # Add monitoring configuration
    with st.expander("Monitoring Configuration"):
        st.write("**Active Monitors:**")
        st.checkbox("Smart Contract Monitor", value=True)
        st.checkbox("Bridge Security Monitor", value=True)
        st.checkbox("Network Monitor", value=True)
        st.checkbox("DeFi Protocol Monitor", value=True)

        st.write("**Alert Thresholds:**")
        st.slider("Critical Alert Threshold", 0, 100, 80)
        st.slider("High Alert Threshold", 0, 100, 60)



def main():
    st.title("Security Incident Response Platform")

    # Sidebar
    st.sidebar.title("Controls")
    selected_page = st.sidebar.radio(
        "Navigate to", ["Dashboard", "Threats", "Responses"]
    )

    if selected_page == "Dashboard":
        show_dashboard()
    elif selected_page == "Threats":
        show_threats()
    else:
        show_responses()


def show_responses():
    st.header("Security Responses")

    # Response Statistics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Active Responses", "3", "+1")
    with col2:
        st.metric("Avg Response Time", "45s", "-5s")
    with col3:
        st.metric("Success Rate", "95%", "+2%")

    # Response Actions Tab
    tab1, tab2 = st.tabs(["Active Responses", "Response History"])

    with tab1:
        show_active_responses()

    with tab2:
        show_response_history()


def show_active_responses():
    """Display active response actions"""
    # Mock data - replace with actual API calls
    active_responses = [
        {
            "id": "RESP-001",
            "threat_id": "THREAT-001",
            "type": "Contract Pause",
            "status": "In Progress",
            "target": "cosmos1abc...",
            "chain": "Osmosis",
            "timestamp": "2024-10-26 15:30:00",
            "severity": "High"
        },
        {
            "id": "RESP-002",
            "threat_id": "THREAT-002",
            "type": "Fund Recovery",
            "status": "Pending",
            "target": "cosmos2xyz...",
            "chain": "Cosmos Hub",
            "timestamp": "2024-10-26 15:45:00",
            "severity": "Critical"
        }
    ]

    # Create DataFrame
    df = pd.DataFrame(active_responses)

    # Add status indicators
    def color_status(status):
        if status == "In Progress":
            return 'background-color: yellow'
        elif status == "Pending":
            return 'background-color: orange'
        return ''

    # Display active responses with styling
    st.subheader("Active Response Actions")
    st.dataframe(
        df.style.applymap(
            color_status,
            subset=['status']
        )
    )

    # Add action buttons
    if st.button("Stop All Responses"):
        st.warning("This will stop all active response actions. Are you sure?")
        if st.button("Confirm Stop"):
            st.success("All responses stopped successfully")


def show_response_history():
    """Display historical response actions"""
    # Mock data - replace with actual API calls
    response_history = [
        {
            "id": "RESP-001",
            "threat_id": "THREAT-001",
            "type": "Contract Pause",
            "result": "Success",
            "target": "cosmos1abc...",
            "chain": "Osmosis",
            "timestamp": "2024-10-26 15:30:00",
            "resolution_time": "45s"
        },
        {
            "id": "RESP-002",
            "threat_id": "THREAT-002",
            "type": "Fund Recovery",
            "result": "Failed",
            "target": "cosmos2xyz...",
            "chain": "Cosmos Hub",
            "timestamp": "2024-10-26 15:45:00",
            "resolution_time": "120s"
        }
    ]

    # Create DataFrame
    df = pd.DataFrame(response_history)

    # Add result indicators
    def color_result(result):
        if result == "Success":
            return 'background-color: lightgreen'
        elif result == "Failed":
            return 'background-color: pink'
        return ''

    # Display response history with styling
    st.subheader("Response History")
    st.dataframe(
        df.style.applymap(
            color_result,
            subset=['result']
        )
    )

    # Add filters
    col1, col2 = st.columns(2)
    with col1:
        st.selectbox("Filter by Chain", ["All", "Osmosis", "Cosmos Hub"])
    with col2:
        st.selectbox("Filter by Result", ["All", "Success", "Failed"])

    # Add analytics
    st.subheader("Response Analytics")

    # Response Time Distribution
    st.write("Response Time Distribution")
    response_times = [45, 60, 30, 120, 90, 75, 40, 55]
    st.line_chart(pd.DataFrame(response_times))

    # Success Rate Over Time
    st.write("Success Rate Over Time")
    success_rates = [95, 93, 97, 94, 96, 98, 95, 97]
    st.line_chart(pd.DataFrame(success_rates))

    # Response Type Distribution
    st.write("Response Type Distribution")
    response_types = {
        "Contract Pause": 45,
        "Fund Recovery": 25,
        "Access Revocation": 20,
        "Parameter Update": 10
    }
    st.bar_chart(pd.DataFrame.from_dict(response_types, orient='index'))


def show_response_details(response_id: str):
    """Show detailed view of a specific response"""
    st.subheader(f"Response Details: {response_id}")

    # Mock data - replace with actual API call
    response_details = {
        "id": response_id,
        "threat_id": "THREAT-001",
        "type": "Contract Pause",
        "status": "In Progress",
        "target": "cosmos1abc...",
        "chain": "Osmosis",
        "timestamp": "2024-10-26 15:30:00",
        "severity": "High",
        "actions": [
            {
                "step": "Verify Threat",
                "status": "Completed",
                "timestamp": "15:30:05"
            },
            {
                "step": "Pause Contract",
                "status": "In Progress",
                "timestamp": "15:30:10"
            },
            {
                "step": "Notify Stakeholders",
                "status": "Pending",
                "timestamp": "-"
            }
        ]
    }

    # Display response details
    col1, col2 = st.columns(2)
    with col1:
        st.write("Response Type:", response_details["type"])
        st.write("Status:", response_details["status"])
        st.write("Target:", response_details["target"])
    with col2:
        st.write("Chain:", response_details["chain"])
        st.write("Timestamp:", response_details["timestamp"])
        st.write("Severity:", response_details["severity"])

    # Display action timeline
    st.subheader("Action Timeline")
    for action in response_details["actions"]:
        if action["status"] == "Completed":
            st.success(f"{action['step']} - {action['timestamp']}")
        elif action["status"] == "In Progress":
            st.warning(f"{action['step']} - {action['timestamp']}")
        else:
            st.info(f"{action['step']} - Pending")

    # Add control buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Pause Response"):
            st.warning("Response paused")
    with col2:
        if st.button("Resume Response"):
            st.success("Response resumed")
    with col3:
        if st.button("Stop Response"):
            st.error("Response stopped")


def show_overview_dashboard():
    st.header("Security Overview")

    # Key Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Security Score",
            value="85%",
            delta="↑ 3%",
            help="Overall security score based on current threats and responses"
        )

    with col2:
        st.metric(
            label="Active Threats",
            value="5",
            delta="-2",
            help="Number of active security threats being monitored"
        )

    with col3:
        st.metric(
            label="Response Time",
            value="45s",
            delta="↓ 5s",
            help="Average time to respond to security incidents"
        )

    with col4:
        st.metric(
            label="Protected Value",
            value="$500M",
            delta="↑ $50M",
            help="Total value of assets protected by ChainSentinel"
        )

    # Threat Distribution Chart
    st.subheader("Threat Distribution")

    threat_data = {
        "Smart Contract Vulnerabilities": 35,
        "Cross-Chain Attacks": 25,
        "DeFi Protocol Exploits": 20,
        "Bridge Security Issues": 15,
        "Network Level Threats": 5
    }

    fig_threats = px.pie(
        values=list(threat_data.values()),
        names=list(threat_data.keys()),
        title="Current Threat Distribution"
    )
    st.plotly_chart(fig_threats)

    # Security Timeline
    st.subheader("Security Timeline")

    timeline_data = pd.DataFrame({
        'timestamp': pd.date_range(start='2024-10-20', periods=7, freq='D'),
        'threats': [4, 6, 3, 7, 2, 5, 4],
        'responses': [4, 5, 3, 7, 2, 5, 3],
        'resolution_time': [50, 45, 42, 48, 40, 45, 43]
    })

    fig_timeline = go.Figure()

    fig_timeline.add_trace(go.Scatter(
        x=timeline_data['timestamp'],
        y=timeline_data['threats'],
        name="Threats",
        line=dict(color='red')
    ))

    fig_timeline.add_trace(go.Scatter(
        x=timeline_data['timestamp'],
        y=timeline_data['responses'],
        name="Responses",
        line=dict(color='green')
    ))

    st.plotly_chart(fig_timeline)

    # Chain Security Status
    st.subheader("Chain Security Status")

    chain_status = {
        "Osmosis": {
            "security_score": 92,
            "active_threats": 2,
            "monitored_contracts": 150,
            "status": "Secure"
        },
        "Cosmos Hub": {
            "security_score": 88,
            "active_threats": 1,
            "monitored_contracts": 200,
            "status": "Secure"
        },
        "Neutron": {
            "security_score": 90,
            "active_threats": 1,
            "monitored_contracts": 100,
            "status": "Secure"
        },
        "Other Chains": {
            "security_score": 85,
            "active_threats": 1,
            "monitored_contracts": 300,
            "status": "Warning"
        }
    }

    chain_df = pd.DataFrame.from_dict(chain_status, orient='index')

    def color_status(val):
        if val == "Secure":
            return 'background-color: lightgreen'
        return 'background-color: lightyellow'

    styled_chain_df = chain_df.style.applymap(
        color_status,
        subset=['status']
    )

    st.dataframe(styled_chain_df)

    # Recent Alerts
    st.subheader("Recent Security Alerts")

    alerts = [
        {
            "timestamp": "2024-10-26 15:45:23",
            "chain": "Osmosis",
            "type": "Smart Contract Vulnerability",
            "severity": "High",
            "status": "Investigating"
        },
        {
            "timestamp": "2024-10-26 15:43:12",
            "chain": "Cosmos Hub",
            "type": "Bridge Security Issue",
            "severity": "Critical",
            "status": "Resolved"
        },
        {
            "timestamp": "2024-10-26 15:40:45",
            "chain": "Neutron",
            "type": "DeFi Protocol Alert",
            "severity": "Medium",
            "status": "Monitoring"
        }
    ]

    alert_df = pd.DataFrame(alerts)

    def color_severity(val):
        if val == "Critical":
            return 'background-color: red; color: white'
        elif val == "High":
            return 'background-color: orange'
        return 'background-color: yellow'

    styled_alert_df = alert_df.style.applymap(
        color_severity,
        subset=['severity']
    )

    st.dataframe(styled_alert_df)

    # Quick Actions
    st.subheader("Quick Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Run Security Scan"):
            st.info("Initiating comprehensive security scan...")

    with col2:
        if st.button("Generate Report"):
            st.info("Generating security report...")

    with col3:
        if st.button("View Alerts"):
            st.info("Opening alert dashboard...")

    # System Health
    st.subheader("System Health")

    health_metrics = {
        "API Status": "Operational",
        "Database Status": "Operational",
        "Monitoring Status": "Active",
        "Last Update": "2 minutes ago"
    }

    col1, col2 = st.columns(2)

    with col1:
        for metric, value in list(health_metrics.items())[:2]:
            st.write(f"**{metric}:** {value}")

    with col2:
        for metric, value in list(health_metrics.items())[2:]:
            st.write(f"**{metric}:** {value}")




def show_dashboard():
    st.header("Security Dashboard")

    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Active Threats", "5", "+2")
    with col2:
        st.metric("Pending Responses", "3", "-1")
    with col3:
        st.metric("Security Score", "85%", "+5%")

    # Threat Chart
    threat_data = pd.DataFrame({
        'Date': pd.date_range(start='2024-01-01', periods=7),
        'Threats': [4, 6, 3, 7, 2, 5, 4]
    })
    st.line_chart(threat_data.set_index('Date'))


def show_threats():
    st.header("Active Threats")

    threats = [
        {"id": "1", "severity": "High", "chain": "Cosmos", "status": "Active"},
        {"id": "2", "severity": "Medium", "chain": "Osmosis", "status": "Pending"}
    ]

    df = pd.DataFrame(threats)
    st.dataframe(df)

if __name__ == "__main__":
    # main()
    show_dashboardv2()