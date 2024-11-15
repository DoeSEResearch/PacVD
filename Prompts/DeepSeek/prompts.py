import logging

def get_model_response(client, prompt):
    logging.info(f"Sending prompt to model:\n{prompt}")
    try:
        response = client.chat.completions.create(
            model="deepseek-coder", messages=[{"role": "user", "content": prompt}], stream=False
        )
        model_output = response.choices[0].message.content.strip().lower()
        logging.info(f"Model output: {model_output}")
        return model_output
    except Exception as e:
        logging.error(f"Error during model prediction: {str(e)}")
        return None

# Basic prompt
def basic_prompt(client, code_document):
    prompt = (
        f"Is the following code vulnerable?\n"
        f"code:\n{code_document.words}\n"
        "Respond with 'yes' or 'no'."
    )
    return get_model_response(client, prompt)

# Direct prompt
def direct_prompt(client, code_document):
    prompt = (
        f"Analyze the following code snippet and associated API information.\n"
        f"Code Snippet:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        "Is the above code vulnerable? Respond with 'yes' or 'no'."
    )
    return get_model_response(client, prompt)

# Chain of Thought (CoT) prompt
def cot_prompt(client, code_document):
    conversation_history = []

    # Round 1: Detailed analysis
    prompt_1 = (
        f"Code:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        "Please provide a detailed summary of the code's functionality, analyze the code structure, "
        "and locate all positions where pointers are constructed and dereferenced."
    )
    conversation_history.append({"role": "user", "content": prompt_1})
    response_1 = client.chat.completions.create(
        model="deepseek-coder", messages=conversation_history, stream=False
    )
    conversation_history.append(response_1.choices[0].message)
    code_analysis = response_1.choices[0].message.content.strip()
    logging.info(f"Response 1: {code_analysis}")

    # Round 2: Vulnerability assessment based on analysis
    prompt_2 = (
        f"Based on the previous analysis:\n'{code_analysis}'\n"
        "Evaluate whether the code has any significant vulnerabilities. Answer 'yes' or 'no' "
        "and provide a brief explanation if applicable."
    )
    conversation_history.append({"role": "user", "content": prompt_2})
    response_2 = client.chat.completions.create(
        model="deepseek-coder", messages=conversation_history, stream=False
    )
    return response_2.choices[0].message.content.strip()

# Role-playing prompt
def role_play_prompt(client, code_document):
    prompt = (
        f"You are an expert vulnerability detection system. Provide precise answers with explanations only when necessary.\n"
        f"Analyze the following code snippet and associated API information.\n"
        f"Code Snippet:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
        "Is the above code vulnerable? Respond with 'yes' or 'no'."
    )
    return get_model_response(client, prompt)

# Contextual multi-round prompt
def contextual_prompt(client, code_document):
    conversation_history = []

    # Round 1: Evaluation of code clarity and maintainability
    prompt_1 = (
        f"You are a professional code reviewer. Evaluate the code snippet for clarity, functionality, and maintainability.\n"
        f"Code Snippet:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}"
    )
    conversation_history.append({"role": "user", "content": prompt_1})
    response_1 = client.chat.completions.create(
        model="deepseek-coder", messages=conversation_history, stream=False
    )
    first_round_output = response_1.choices[0].message.content.strip()
    conversation_history.append(response_1.choices[0].message)
    logging.info(f"Round 1 Response: {first_round_output}")

    # Round 2: Security assessment based on observations
    prompt_2 = (
        f"Based on your initial observations:\n'{first_round_output}'\n"
        "Does the code meet security standards? Answer 'yes' or 'no'."
    )
    conversation_history.append({"role": "user", "content": prompt_2})
    response_2 = client.chat.completions.create(
        model="deepseek-coder", messages=conversation_history, stream=False
    )
    return response_2.choices[0].message.content.strip()


# Few-shot learning prompt
def few_shot_prompt(client, code_document):
    prompt = (
        "You are an AI assistant specialized in detecting security vulnerabilities in code. "
        "\n\nExamples:"
        "\n\nCode Snippet 1:\n"
        "Code:\nint jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n{\n    return (tsfb->numlvls > 0 && jas_seq2d_size(a)) ?\n      jpc_tsfb_synthesize2(tsfb,\n      jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),\n      jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),\n      jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;\n}\n"
        "API Information:\nIn the function jpc_tsfb_synthesize2, no branches allocate memory.\nIn the function jpc_tsfb_synthesize2, memory is not released on any branches.\nOutput: no"
        "\n\nCode Snippet 2:\n"
        "Code:\nstatic void read_const_block_data(ALSDecContext *ctx, ALSBlockData *bd)\n{\n    ALSSpecificConfig *sconf = &ctx->sconf;\n    AVCodecContext *avctx    = ctx->avctx;\n    GetBitContext *gb        = &ctx->gb;\n\n    *bd->raw_samples = 0;\n    *bd->const_block = get_bits1(gb);    // 1 = constant value, 0 = zero block (silence)\n    bd->js_blocks    = get_bits1(gb);\n\n    // skip 5 reserved bits\n    skip_bits(gb, 5);\n\n    if (*bd->const_block) {\n        unsigned int const_val_bits = sconf->floating ? 24 : avctx->bits_per_raw_sample;\n        *bd->raw_samples = get_sbits_long(gb, const_val_bits);\n    }\n\n    // ensure constant block decoding by reusing this field\n    *bd->const_block = 1;\n}\n"
        "API Information:\nIn the function skip_bits, no branches allocate memory.\nIn the function skip_bits, memory is not released on any branches.\nIn the function get_sbits_long, no branches allocate memory.\nIn the function get_sbits_long, memory is not released on any branches.\nIn the function get_bits1, no branches allocate memory.\nIn the function get_bits1, memory is not released on any branches.\nOutput: yes"
        "Refer to above examples, Analyze the following code snippet and associated API information. Provide a detailed response on whether the code is vulnerable. "
        "If the code is vulnerable, start your answer with 'yes' followed by a brief explanation. If the code is not vulnerable, start your answer with 'no' followed by reasoning."
        f"\n\nCode Snippet:\nCode:\n{code_document.words}"
        f"\nAPI Information:\n{code_document.API_sequence}"
    )
    return get_model_response(client, prompt)


# Comparison prompt
def comparison_prompt(client, code_document):
    prompt = (
        "You are an AI assistant specialized in detecting security vulnerabilities in code. "
        "Analyze the following code snippets, comparing the 'Before Fix' and 'After Fix' versions to understand the vulnerability fix. "
        "Evaluate if the 'Before Fix' version is vulnerable, and if so, explain how the 'After Fix' version mitigates this issue.\n\n"
        "Example 1:\n"
        "Before Fix:\n"
        "```c\n"
        "int jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n"
        "{\n"
        "    return (tsfb->numlvls > 0) ? jpc_tsfb_synthesize2(tsfb,\n"
        "    jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),\n"
        "    jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),\n"
        "    jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;\n"
        "}\n"
        "```\n"
        "After Fix:\n"
        "```c\n"
        "int jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)\n"
        "{\n"
        "    return (tsfb->numlvls > 0 && jas_seq2d_size(a)) ? jpc_tsfb_synthesize2(tsfb,\n"
        "    jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),\n"
        "    jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),\n"
        "    jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;\n"
        "}\n"
        "```\n"
        f"Refer to the examples above. Now, Analyze the following code snippet and associated API information. answer with 'yes' if it is vulnerable, or 'no' if it is not.\n\n"
        f"Code:\n{code_document.words}\n"
        f"API Information:\n{code_document.API_sequence}\n"
    )
    return get_model_response(client, prompt)


# General model response handler
def get_model_response(client, prompt):
    logging.info(f"Sending prompt to model:\n{prompt}")
    try:
        response = client.chat.completions.create(
            model="deepseek-coder", messages=[{"role": "user", "content": prompt}], stream=False
        )
        return response.choices[0].message.content.strip().lower()
    except Exception as e:
        logging.error(f"Error during model prediction: {str(e)}")
        return None


# Prompt function mapping
PROMPT_FUNCTIONS = {
    "basic": basic_prompt,
    "direct": direct_prompt,
    "cot": cot_prompt,
    "role_play": role_play_prompt,
    "contextual": contextual_prompt,
    "few_shot": few_shot_prompt,
    "comparison": comparison_prompt
}