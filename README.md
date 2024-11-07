# **PacVD** ---- **P**rimitive **A**PI Abstraction and **C**ontext-Enhanced **V**ulnerability **D**etection method utilizing Large Language Models

This repository provides a set of automated steps to analyze CVE-related vulnerabilities, extract information,  generate summaries of Primitive API, and test LLMs with different prompting engineering strategies.



## Steps Overview

### Data Preprocessing

**1. Extract CVE Information**

- **Script**: `Data_Preprocess/extract_NVD.py`
- **Description**: Find the relevant files for each CVE and extract the necessary information.
- **Data Structure**:
  
  ```python
  CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID')
  ```

**2. Find Parent Commit**

- **Script**: `Data_Preprocess/get_parent_sha.py`
- **Description**: Retrieve the parent commit for each CVE-related commit.

**3. Checkout Vulnerable and Non-Vulnerable Projects**

- **Script**: `Data_Preprocess/get_projects.py`
- **Description**: Checkout both vulnerable and non-vulnerable versions of the projects for analysis.

**4. Analyze Projects Using Joern**

- **Script**: `Data_Preprocess/run_joern.py`
- **Description**: Use Joern to analyze the vulnerable and non-vulnerable versions of the projects.

### Extract Branch Summaries

- **Script**: `Primitive_API_Abstraction/extract_API_summary.py`
- **Description**: Extract branch summaries and represent them in three different formats.

### Prompt Engineering for LLMs

- **Script**: `Prompts/ChatGPT`,`Prompts/Codellama`,`Prompts/DeepSeek`
- **Description**: Testing GPT-4o/CodeLLaMA-34b/DeepSeek-v2.5 with different prompt engineering strategies.

## Prerequisites

- Python 3.10
- Joern 2.0.445
- JDK 19
- Vllm 0.6.2

## Usage

1. Clone this repository:
   ```sh
   git clone https://github.com/DoeSEResearch/PacVD.git
   cd Data_Preprocess
   python extract_NVD.py
   python get_parent_sha.py
   python get_projects.py
   python run_joern.py
   cd Primitive_API_Abstraction
   python extract_API_summary.py --server 47 --vulnerable vul --max_workers 5 --IterationLayer 3
   cd Prompts/ChatGPT
   python run_coder_A_C_E.py
   python judge_A_C_E.py
   ```
   
2. Follow the steps outlined above to execute the scripts in sequence.

3. Modify the scripts as needed to suit your specific analysis requirements.

