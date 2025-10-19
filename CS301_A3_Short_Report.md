# CS301 – Assessment 3: MVP Development
**Student:** Shoail Rafiq (270024464)  
**Project:** Network Sniffer & Scanner MVP  
**Course:** CS301 – Investigative Studio II  

---

## 1. Introduction
This project is a working prototype of my Network Sniffer and Scanner Application that I proposed earlier this year. The goal was to create a simple, lightweight educational tool that lets users view network activity and perform quick port scans without the complexity of professional tools like Wireshark or Nmap.  

The idea behind this MVP is to help students and beginners understand how packets move through a network, what protocols are being used, and how ports are scanned—all while keeping everything legal, safe, and easy to follow.  

The final MVP was developed using **Python**, with **Scapy** handling packet capture, **python-nmap** for port scanning, and **Tkinter** for the interface. It focuses on the educational side of network analysis rather than deep data inspection. The app runs smoothly on low-spec hardware, making it ideal for classrooms or anyone learning from home.

---

## 2. What Was Achieved
All the main features planned in the proposal and IDD were completed and tested.  

- **Packet Capture:**  
  The app can capture live network packets and show them in real-time inside a scrolling table. It records metadata like timestamp, source, destination, protocol, and packet length. It doesn’t capture payloads, keeping it ethical and lightweight.  

- **Port Scanning:**  
  Using python-nmap, the user can run a quick scan on localhost or any target within the local network. It lists open ports clearly and quickly.  

- **Graphical Interface:**  
  The GUI is clean, built with Tkinter, and divided into four simple screens — Home, Packet Capture, Port Scanner, and Settings. Everything is labelled so even beginners can follow it.  

- **CSV Export:**  
  Captured data or scan results can be saved to a CSV file in the `evidence/` folder for reports or submission.  

- **Consent Prompt:**  
  A user consent window appears before any scanning or sniffing can begin. This was added to make sure the tool is used ethically and in line with classroom safety rules.

All of these make the MVP fully usable, stable, and educational — it runs the way I designed it to in the proposal.

---

## 3. Limitations
A few planned extras had to be skipped to meet the submission deadline and due to health setbacks earlier this semester.  

- The **SQLite database** for persistent storage is coded but not yet fully connected to the GUI.  
- **Filter presets** like “HTTP only” or “DNS traffic only” are not yet added. Users can still manually enter a BPF filter if they want.  
- The app can only do **TCP scans**, not UDP.  
- There’s no automatic report generation (PDF or HTML export), though CSV exporting works fine.  

These aren’t major issues for an MVP. The goal was to have a working, demonstrable app — and that’s been achieved.

---

## 4. Market and Monetary Viability
This MVP fills a gap in the market between complex professional tools and overly simple network utilities. Most sniffers like Wireshark are great but hard for new users to learn.  

**Market viability:**  
The tool can be used in teaching environments, workshops, or student projects. It’s aimed at beginners who want to understand the basics of networking and cybersecurity.  

**Monetary viability:**  
The app itself is open-source and free to use, but there’s potential for future educational versions — like a classroom edition with dashboards or reporting tools — which could be monetised for institutions or training providers.

---

## 5. Security, Privacy, and Ethics
Security and ethics were key from day one. Everything in this app is designed to stay within legal and moral limits.  

- The app **asks for consent** before doing anything.  
- It only logs **metadata**, never payloads or sensitive information.  
- Data is saved **locally**, never uploaded or sent anywhere online.  
- The interface clearly shows when the app is active, so the user knows what’s happening.  

This keeps the app safe to use for learning and ensures that no network data is collected without permission.

---

## 6. Unique Selling Point and Innovation
What makes this project stand out is how approachable it is.  
It’s built around education, not advanced cybersecurity work.  

The key differences compared to other tools are:
- Focus on **metadata only**, keeping privacy intact.  
- **Built-in consent workflow**, which most sniffers don’t include.  
- **Simple Tkinter interface** that helps users see packet activity clearly.  
- **Dual functionality** — a sniffer and a scanner in one simple app.  

It’s lightweight, portable, and modular, which means more advanced features can be added easily later without breaking the base design.

---

## 7. Documentation and User Support
The README file on GitHub includes full setup instructions, screenshots, dependencies, and ethical notes. It also explains how to run the app (`python -m app.gui_app`) and test modules individually.  

It’s designed so that anyone — even someone new to Python — can clone the repo and get the app running with minimal help. For a classroom setup, the tutor could easily show students how to capture local traffic in less than 10 minutes.

---

## 8. Reflection
This project was built during a challenging time for me. I’ve had ongoing health issues, including surgery for pancreatic cysts and recovery after getting a new insulin pump. It caused some delays, but I managed to stay on track by focusing on one section at a time and working in short bursts.  

Breaking the project into small, testable modules helped me keep progress steady even when I wasn’t at full strength. This MVP is the result of persistence, planning, and simplifying the workload into manageable steps.  

I’m proud that the final product works exactly as intended and fits the goals from my proposal and IDD. It’s not perfect yet, but it’s stable, usable, and ready for the next stage of development in CS302.

---

