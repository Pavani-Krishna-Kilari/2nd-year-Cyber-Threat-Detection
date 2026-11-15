# Artificial Neural Network Architectures for Event-Profile-Based Threat Detection

## Architectural Design & Justifications (FCNN, 1D-CNN, LSTM)

**Project:** AI-Based SIEM System for Cyber Threat Detection  
**Input Dimensions:** 8 Basepoint Cosine Similarity Metrics (`bp_01` to `bp_08`)  
**Target:** Binary Detection (`target_binary`: 0 = NORMAL/BENIGN, 1 = THREAT) and Multiclass Threat Attribution (`target_multiclass`: 0 = BENIGN, 1 = FTP-Patator, 2 = SSH-Patator)

---

## 1. Input Representation Overview

In Phase 3 (Event Profile Generation), the 5 derived flow/set-level security events (`HIGH_FLOW_RATE`, `HIGH_PACKET_RATE`, `HIGH_BYTE_RATE`, `SYN_ACTIVITY`, `SHORT_REPEATED_CONNECTIONS`) are aggregated across 10-minute sliding windows (stepped every 60 seconds) for each communicating `(source_ip, destination_ip)` pair.

After TF-IDF vectorization and greedy basepoint selection, each event set is mapped to an **Event Profile**:
$$\mathbf{p} = \big[ \text{sim}(\mathbf{v}, \mathbf{b}_1),\, \text{sim}(\mathbf{v}, \mathbf{b}_2),\, \dots,\, \text{sim}(\mathbf{v}, \mathbf{b}_8) \big]^T \in [0, 1]^8$$
where $\mathbf{b}_i$ are the 8 selected prototype basepoint vectors in 5-dimensional event space.

---

## 2. FCNN (Fully Connected Neural Network)

### Architectural Justification
The 8 basepoint cosine similarities quantify geometric alignment with 8 distinct prototype security behaviors in the derived event space. Because these 8 values are dense continuous coordinates, an FCNN (Multi-Layer Perceptron) is theoretically optimal for learning arbitrary non-linear boundaries across the entire 8-dimensional space simultaneously.

### Input Representation & Layer Design
- **Input:** Vector $\mathbf{x} \in \mathbb{R}^8$
- **Hidden Layer 1:** Dense(64, activation='relu', kernel_regularizer=L2(1e-4))
- **Normalization & Regularization 1:** BatchNormalization() + Dropout(0.3)
- **Hidden Layer 2:** Dense(32, activation='relu')
- **Normalization & Regularization 2:** BatchNormalization() + Dropout(0.2)
- **Hidden Layer 3:** Dense(16, activation='relu')
- **Output Layer:** Dense(1, activation='sigmoid') for binary threat probability $P_{\text{FCNN}}(\text{Threat} \mid \mathbf{x})$.

---

## 3. 1D-CNN (Convolutional Neural Network)

### Architectural Justification
In classical computer vision and time-series analysis, convolutions exploit spatial locality. In the context of event profiles:
1. **Basepoint Spectrum Representation:**
   The 8 basepoints are not arbitrary random numbers; they represent an ordered set of cluster centroids derived from greedy distance optimization over rare security events. The 8 basepoint values form a similarity profile or "spectrum" characterizing the communication set.
2. **Local Correlation & Sub-Signature Detection:**
   A 1D convolutional filter of kernel size $k=3$ slides over the 8-dimensional profile vector. Each receptive field computes dot products across adjacent basepoints, identifying localized co-occurrence patterns (e.g. concurrent activation of high flow rate and high SYN activity).
3. **Translational & Scale Robustness:**
   Subsequent Max-Pooling / Global Pooling extracts invariant feature representations, condensing distributed basepoint activations into a rich latent representation.

### Input Representation & Layer Design
- **Input:** 2D Tensor $\mathbf{X} \in \mathbb{R}^{8 \times 1}$ (sequence length 8, 1 input channel)
- **Conv1D Layer 1:** 32 filters, kernel size 3, padding='same', activation='relu'
- **Normalization:** BatchNormalization()
- **Conv1D Layer 2:** 64 filters, kernel size 3, padding='same', activation='relu'
- **Pooling:** GlobalMaxPooling1D() (extracts the dominant localized pattern across all basepoint combinations)
- **Dense Projection:** Dense(32, activation='relu') + Dropout(0.2)
- **Output Layer:** Dense(1, activation='sigmoid') for binary threat probability $P_{\text{CNN}}(\text{Threat} \mid \mathbf{X})$.

---

## 4. LSTM (Long Short-Term Memory)

### Critical Methodological Problem & Resolution
**The Problem:**
In our event profile generation, the 8 basepoint dimensions of a single event profile are **concurrency-based coordinates** representing simultaneous similarities to 8 centroids in 5D event space. They are NOT time steps.
*Treating $\text{bp\_01}$ as time 1, $\text{bp\_02}$ as time 2, ..., $\text{bp\_08}$ as time 8 would be methodologically false and physically baseless.*

**The Rigorous Justification & Formulation:**
In network traffic monitoring and SIEM, cyber threats (specifically brute-force attacks such as FTP-Patator and SSH-Patator) unfold dynamically over continuous time.
As the sliding window advances through time ($W_0, W_1, W_2, \dots$ at 60-second steps), a communicating host pair $(src\_ip, dst\_ip)$ generates a genuine **temporal sequence of event profiles**:
$$\mathbf{S}_{(src, dst)} = \big[ \mathbf{p}(t - T + 1),\, \dots,\, \mathbf{p}(t - 1),\, \mathbf{p}(t) \big] \in \mathbb{R}^{T \times 8}$$
where each time step $t$ receives the complete 8-dimensional event profile $\mathbf{p}(t) \in \mathbb{R}^8$.

In this formulation:
1. **Physical Meaning:** The temporal dimension represents actual chronological progression across sliding windows (e.g. $T=3$ or $T=5$ windows).
2. **Behavioral Dynamics:** Benign traffic often exhibits temporary, bursty spikes that subside rapidly, whereas Patator brute-force attacks sustain repeated, elevated rate profiles across successive sliding windows.
3. **Recurrent Gating:** The LSTM cell's forget and input gates learn to detect the sustained recurrence of high-rate and SYN basepoint signatures across consecutive minutes.
4. **Handling Single-Window / Isolated Evaluation (Stateless Fallback):**
   When an operator performs isolated single-window testing or during cold-start (where only one window profile is provided), the sequence length is $T=1$ (shape $(1, 8)$). The LSTM processes the complete 8D vector as a single time step without distorting feature semantics.

### Layer Design
- **Input:** Tensor $\mathbf{X}_{\text{seq}} \in \mathbb{R}^{T \times 8}$ (where $T \ge 1$ time steps, each with 8 basepoint features)
- **Bidirectional LSTM Layer:** 32 units (16 forward, 16 backward), return_sequences=False
- **Dense Layer:** Dense(16, activation='relu') + Dropout(0.2)
- **Output Layer:** Dense(1, activation='sigmoid') for binary threat probability $P_{\text{LSTM}}(\text{Threat} \mid \mathbf{X}_{\text{seq}})$.

---

## 5. Soft-Voting Ensemble Architecture

### Single Unified SIEM Verdict
The SIEM system must present **ONE definitive verdict**: `THREAT` or `NORMAL`, rather than three competing decisions.

### Formulation
Given the calibrated probabilities from each network:
$$P_{\text{FCNN}} = P(\text{Threat} \mid \mathbf{x}), \quad P_{\text{CNN}} = P(\text{Threat} \mid \mathbf{x}), \quad P_{\text{LSTM}} = P(\text{Threat} \mid \mathbf{x})$$

The unified threat confidence is the soft-voted weighted average:
$$P_{\text{ensemble}} = w_{\text{FCNN}} \cdot P_{\text{FCNN}} + w_{\text{CNN}} \cdot P_{\text{CNN}} + w_{\text{LSTM}} \cdot P_{\text{LSTM}}$$
subject to $\sum w_i = 1$ (default equal weights $w_i = \frac{1}{3}$, tunable via validation F1-optimization).

The unified SIEM verdict is:
$$\text{Verdict} = \begin{cases} \text{THREAT}, & \text{if } P_{\text{ensemble}} \ge \tau \\ \text{NORMAL}, & \text{if } P_{\text{ensemble}} < \tau \end{cases}$$
where the decision threshold $\tau \in [0.1, 0.9]$ is calibrated on validation data to achieve the desired Precision-Recall balance for SOC operations.
