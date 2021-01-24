# Cisco MDS Traffic Monitoring (MTM)
Cisco MDS 9000 monitoring using Grafana and InfluxDB

[Click here to check out Cisco UCS Traffic Monitoring (UTM)](https://github.com/paregupt/ucs_traffic_monitor). This project is inspired by UTM.


Global Inventory
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-inventory-over-time.png)

Digital Optical Monitoring of SFP (Hottest, Coldest, Lowest RX and TX Power)
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-dom-top-10.png)

Digital Optical Monitoring of SFP
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-dom.png)

Top-10 ports (Traffic, Congestion, Errors, etc.)
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-top-10-ports.png)

Switchport monitoring 
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-switchport-stats.png)

Port-Channel traffic distribution
![enter image description here](https://www.since2k7.com/wp-content/uploads/2021/01/mtm-pc-traffic-utilization.png)

and much more...

## Architecture
The MTM collector (mds_traffic_monitor_*.py) pulls stats from Cisco MDS switches using NX-API. The stats are normalized and corrected before writing to InfluxDB. Finally, Grafana provides the visualization and use-cases.

- **Data source**: [Cisco MDS Switches via NXAPI)](https://developer.cisco.com/docs/mds-9000-nx-api-reference/), read-only account is enough
- **Data storage**: [InfluxDB](https://github.com/influxdata/influxdb), a time-series database
- **Visualization**: [Grafana](https://github.com/grafana/grafana)

## Installation
- Tested OS: CentOS 7.x. Should work on other OS also.
- Python version: Version 3 only. Should be able to work on Python 2 also with minor modification.

- DIY Installation: Self install the required packages
