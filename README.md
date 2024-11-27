# Automated Vulnerability Analysis Steps

This repository provides a set of automated steps to analyze CVE-related vulnerabilities, extract information, and generate summaries using various tools.

## Steps Overview

### 1. Extract CVE Information

- **Script**: `Data_Preprocess/extract_NVD.py`
- **Description**: Find the relevant files for each CVE and extract the necessary information.
- **Data Structure**:
  ```python
  CodeDocument = collections.namedtuple('CodeDocument', 'words cls project CVE_ID CWE_ID commit parent_commit file_name file_ID function_ID')
  ```

### 2. Find Parent Commit

- **Script**: `Data_Preprocess/get_parent_sha.py`
- **Description**: Retrieve the parent commit for each CVE-related commit.

### 3. Checkout Vulnerable and Non-Vulnerable Projects

- **Script**: `Data_Preprocess/get_projects.py`
- **Description**: Checkout both vulnerable and non-vulnerable versions of the projects for analysis.

### 4. Analyze Projects Using Joern

- **Script**: `Data_Preprocess/run_joern.py`
- **Description**: Use Joern to analyze the vulnerable and non-vulnerable versions of the projects.

### 5. Extract Branch Summaries

- **Script**: `Primitive_API_Abstraction/extract_API_summary_fuzzy_branches.py`
- **Description**: Extract branch summaries and represent them in three different formats.


### 6. Test the Models

- **Scripts**:
    - `Prompts/ChatGPT(Codellama,DeepSeek)/run.py`
    - `Prompts/ChatGPT(Codellama,DeepSeek)/run_baseline.py`
    - `Prompts/ChatGPT(Codellama,DeepSeek)/prompts.py`
    - `Prompts/ChatGPT(Codellama,DeepSeek)/judge.py`

- **Supported Models**

This repository supports three models for vulnerability analysis:
1. **ChatGPT**: Advanced contextual understanding.
2. **DeepSeek**: High-performance multi-tasking for vulnerability detection.
3. **CodeLlama**: Optimized for large-scale code analysis.

- **Each model has its own set of scripts located in specific directories:**
    - `Prompts/ChatGPT/`
    - `Prompts/DeepSeek/`
    - `Prompts/CodeLlama/`

- **Each script (`run.py`, `run_baseline.py`, `prompts.py`, and `judge.py`) has the same command-line structure but is tailored for the respective model.**

- **Data Levels and Their Representation**

Different datasets correspond to distinct levels of Primitive API Abstraction:

| Dataset Name | Abstraction Level | Description                                             |
|--------------|-------------------|---------------------------------------------------------|
| A1.pkl       | API-Level-1       | The highest abstraction, using fuzzy branch summary information. |
| A2.pkl       | API-Level-2       | Concrete branches of different Primitive APIs.          |
| A3.pkl       | API-Level-3       | Concrete branches combined with the number of calls.    |
| A4.pkl       | API-Level-4       | Concrete branches combined with key variables.          |
| Basic.pkl    | W/O-Level         | No contextual API information is provided.              |

---

**Script**: `run.py`

- **Purpose**:  
  Run the main analysis pipeline for the specified model. This script processes datasets with different levels of API abstraction and uses various prompt types.

- **Usage**:  
  ```bash
  python run.py --api_key <YOUR_API_KEY> --data_file <DATA_FILE.pkl> --prompt_type <PROMPT_TYPE>
  ```

- **Parameters**:
    - `--api_key`: The API key for the model (required).
    - `--data_file`: Dataset file in `.pkl` format, representing different API abstraction levels.
    - `--prompt_type`: The type of prompt to use, defined in `prompts.py`. Supported options:
        - `basic`
        - `direct`
        - `cot`
        - `role_play`
        - `contextual`
        - `few_shot`
        - `comparison`

- **Example Commands**:
    - **ChatGPT**:
      ```bash
      cd Prompts/ChatGPT
      python run.py --api_key sk-<your_api_key> --data_file A1.pkl --prompt_type basic
      ```

    - **DeepSeek**:
      ```bash
      cd Prompts/DeepSeek
      python run.py --api_key sk-<your_api_key> --data_file A2.pkl --prompt_type cot
      ```

    - **CodeLlama**:
      ```bash
      cd Prompts/CodeLlama
      python run.py --data_file Basic.pkl --prompt_type few_shot
      ```

- **Output**:  
  Results are saved in `../../result` as:
    - `gpt-4o_<prompt_type>_<dataset_name>.json`
    - `gpt-4o_<prompt_type>_<dataset_name>.xlsx`

---

**Script**: `run_baseline.py`

- **Purpose**:  
  Evaluates the model’s performance on baseline datasets without API summaries (W/O-Level). It serves as a benchmark for comparison.

- **Usage**:  
  ```bash
  python run_baseline.py --api_key <YOUR_API_KEY> --callee_key <whole_callees/random_sampled_callees/API_sample_callees/similar_sampled_callees/hierarchy_sampled_callees>
  ```

- **Example**:
    - **ChatGPT**:
      ```bash
      cd Prompts/ChatGPT
      python run_baseline.py --api_key sk-<your_api_key> --callee_key whole_callees
      ```

    - **DeepSeek**:
      
      ```bash
      cd Prompts/DeepSeek
      python run_baseline.py --api_key sk-<your_api_key> --callee_key API_sample_callees
      ```
    - **CodeLlama**:
      ```bash
      cd Prompts/CodeLlama
      python run_baseline.py --callee_key random_sampled_callees
      ```
---

**Script**: `prompts.py`

- **Purpose**:  
  Contains prompt formatting logic. Each model uses its own version of `prompts.py`, optimized for its capabilities. The following prompt types are supported:
    1. `basic_prompt`: Simple yes/no vulnerability evaluation.
    2. `direct_prompt`: Uses API summaries for a direct vulnerability assessment.
    3. `cot_prompt`: Chain-of-thought reasoning for detailed analysis.
    4. `role_play_prompt`: Simulates a vulnerability detection expert’s response.
    5. `contextual_prompt`: Multi-round contextual prompt focusing on resource management.
    6. `few_shot_prompt`: Includes examples for few-shot learning.
    7. `comparison_prompt`: Compares “Before Fix” and “After Fix” code snippets.

---

**Script**: `judge.py`

- **Purpose**:  
  Evaluates the model’s predictions and calculates performance metrics.

- **Usage**:  
  ```bash
  python judge.py --results_file <RESULTS_FILE.json>
  ```

- **Metrics**:
    - Accuracy
    - Precision
    - Recall
    - F1 Score
    - Matthews Correlation Coefficient (MCC)
    - Confusion Matrix

- **Example**:

    - **For ChatGPT**:
      ```bash
      cd Prompts/ChatGPT
      python judge.py --results_file ../../result/gpt-4o_basic_A1.json
      ```

    - **For DeepSeek**:
      ```bash
      cd Prompts/DeepSeek
      python judge.py --results_file ../../result/deepseek_direct_A2.json
      ```
    - **For CodeLlama**:
      ```bash
      cd Prompts/CodeLlama
      python judge.py --results_file ../../result/codellama_role_play_A1.json
      ```
---

## Prerequisites

- Python 3.10.14
- Joern
- Git

## Usage

1. Clone this repository:
   ```sh
   git clone https://github.com/your-repository-url
   cd your-repository
   ```

2. Follow the steps outlined above to execute the scripts in sequence.

3. Modify the scripts as needed to suit your specific analysis requirements.

