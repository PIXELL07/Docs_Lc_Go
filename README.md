# Log Analyzer and AI-Powered Code Reviewer

This repository contains two main applications:

1. **Log Analyzer**: A tool for analyzing log files, detecting anomalies, and generating actionable insights using AI.
2. **AI-Powered Code Reviewer**: A utility for reviewing Go code files, providing feedback on style, correctness, and improvements.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Log Analyzer](#log-analyzer)
  - [AI-Powered Code Reviewer](#ai-powered-code-reviewer)
- [Sample Logs](#sample-logs)
- [Dependencies](#dependencies)
- [License](#license)

---

## Features

### Log Analyzer
- Parses structured and unstructured log files.
- Detects anomalies, spikes, and critical issues.
- Generates AI-driven recommendations and insights.
- Supports real-time monitoring with alerting capabilities (e.g., Slack integration).

### AI-Powered Code Reviewer
- Reviews Go code files for style, correctness, and improvements.
- Supports reviewing individual files, directories, or Git changes.
- Utilizes OpenAI's language model for intelligent feedback.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/log-analyzer-and-code-reviewer.git
   cd log-analyzer-and-code-reviewer

2. Install dependencies:
   go mod tidy

3. Set up your OpenAI API key: 
export OPENAI_API_KEY="your_api_key_here"

