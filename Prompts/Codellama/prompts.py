import logging

# Basic prompt
def basic_prompt(code_document):
    return (
        f"Is the following code vulnerable?\n"
        f"Code:\n{code_document.words}\n"
        "Respond with 'yes' or 'no'."
    )

# Direct prompt
def direct_prompt(code_document):
    return (
        f"Analyze the following code snippet and associated API information. "
        f"\nCode Snippet:\n{code_document.words}"
        f"\nAPI Information:\n{code_document.API_sequence}"
        "Is the above code vulnerable? Respond with 'yes' or 'no'."
    )

# Chain of Thought (CoT) prompt
def cot_prompt(code_document, previous_analysis=None):
    if previous_analysis is None:
        # Initial analysis
        return (
            f"Code:\n{code_document.words}\n"
            f"API Information:\n{code_document.API_sequence}\n"
            "Please provide a detailed summary of the code's functionality, analyze the code structure, "
            "and locate all positions where pointers are constructed. Also, identify all locations where pointers are dereferenced."
        )
    else:
        # Follow-up evaluation
        return (
            f"Based on the analysis of the code: '{previous_analysis}', evaluate whether the code has any significant vulnerabilities. "
            "Answer 'yes' or 'no' to indicate if there is a significant risk. If there is a risk, please provide the specific reason."
        )

# Role-play prompt
def role_play_prompt(code_document):
    return (
        f"You are an expert vulnerability detection system. Provide precise and direct answers with explanations only when necessary."
        f"\nAnalyze the following code snippet and associated API information."
        f"\nCode Snippet:\n{code_document.words}"
        f"\nAPI Information:\n{code_document.API_sequence}"
        "Is the above code vulnerable? Respond with 'yes' or 'no'."
    )

# Contextual multi-round prompt
def contextual_prompt(code_document, previous_analysis=None):
    if previous_analysis is None:
        # Initial analysis
        return (
            "You are a professional code reviewer. Analyze the code snippet for clarity, functionality, and resource management practices. "
            "Use the API information to understand code structure, identify all resource allocations, and verify if they are properly cleaned up."
            f"\nCode Snippet:\n{code_document.words}\n"
            f"API Information:\n{code_document.API_sequence}"
        )
    else:
        # Follow-up evaluation
        return (
            f"Based on the analysis result: '{previous_analysis}', make a final determination on whether improvements are needed "
            "in resource allocation and cleanup. Answer 'yes' if any improvements are recommended, or 'no' if the code meets all criteria."
        )

# Few-shot learning prompt
def few_shot_prompt(code_document):
    return (
        "You are an AI assistant specialized in detecting security vulnerabilities in code.\n\n"
        "Examples:\n\n"
        "Code Snippet 1:\n"
        "Code:\nint jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n"
        "{\n    return (tsfb->numlvls > 0 && jas_seq2d_size(a)) ?\n"
        "    jpc_tsfb_synthesize2(tsfb, jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),\n"
        "    jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),\n"
        "    jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;\n}\n"
        "API Information:\nNo memory allocation or release.\nOutput: no\n\n"
        "Code Snippet 2:\n"
        "Code:\nstatic void read_const_block_data(ALSDecContext *ctx, ALSBlockData *bd)\n"
        "{\n    *bd->raw_samples = 0;\n    *bd->const_block = get_bits1(ctx->gb);\n}\n"
        "API Information:\nMemory is allocated but not released.\nOutput: yes\n\n"
        "Now, analyze the following code snippet:\n"
        f"Code:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        "Provide a detailed response with 'yes' or 'no'."
    )

# Comparison prompt
def comparison_prompt(code_document):
    return (
        "You are an AI assistant specialized in detecting security vulnerabilities in code.\n"
        "Analyze the following code snippets, comparing the 'Before Fix' and 'After Fix' versions to understand the vulnerability fix.\n\n"
        "Example:\n"
        "Before Fix:\n"
        "```c\nint jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n"
        "{\n    return (tsfb->numlvls > 0) ? jpc_tsfb_synthesize2(tsfb, a->data, tsfb->numlvls - 1) : 0;\n}\n```\n"
        "After Fix:\n"
        "```c\nint jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n"
        "{\n    return (tsfb->numlvls > 0 && a != NULL) ? jpc_tsfb_synthesize2(tsfb, a->data, tsfb->numlvls - 1) : 0;\n}\n```\n"
        f"Now, analyze the following 'Before Fix' version:\nCode:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        "Provide a 'yes' or 'no' answer with a short explanation."
    )

# Map prompt types to functions
PROMPT_FUNCTIONS = {
    "basic": basic_prompt,
    "direct": direct_prompt,
    "cot": cot_prompt,
    "role_play": role_play_prompt,
    "contextual": contextual_prompt,
    "few_shot": few_shot_prompt,
    "comparison": comparison_prompt
}