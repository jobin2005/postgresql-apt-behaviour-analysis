# Weekly Status Report — Deep Q-Learning Security Extension

=======
1. **Research Idea for implementation**:
Using **Experience Replay** and **Target Networks** within a **Deep Q-Network (DQN)** to model stateful, temporal database session sequences. This allows the system to detect multi-stage APT patterns (e.g., Recon $\rightarrow$ Lateral Movement $\rightarrow$ Exfiltration) that static anomaly detection misses. By mapping these sequences to the **Linux Process PID**, we can observe the behavioral evolution of an attacker.

2. **The reference research paper link from where that idea is born**:
M. A. Hossain, “*Deep Q-learning intrusion detection system (DQ-IDS): A novel reinforcement learning approach for adaptive and self-learning cybersecurity*,” **ICT Express**, vol. 11, pp. 875–880, 2025.
[Link to Paper Topic (ICT Express)](https://www.sciencedirect.com/journal/ict-express)
=======

### This Week's Implementation Progress:
- [x] **DQL Agent Core**: Completed the Double DQN logic for session sequence analysis.
- [x] **PostgreSQL 18.3 Extension (`apt_guard`)**: Developed the C-based extension skeleton with the **Executor Hook**.
- [x] **Kernel Integration**: Mapped database `session_id` to the underlying **Linux Process Descriptor (`task_struct`)** to allow for kernel-level behavioral telemetry.
- [x] **Real-time Dashboard**: Built the dark-mode monitoring interface to visualize threat scores.

*Team: Adithyan M C, Asiya Salam, Jobin A J, Sreedeep Rajeevan*
