from flask import Flask, request, jsonify
import re
from openai import OpenAI
import json

client = OpenAI(
    api_key="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",
)

app = Flask(__name__)


@app.route('/inspect')
def home():
    content = request.json
    content_list = content["contents"]

    if len(content_list) == 0:
        return content_list, 200

    if not content["policy"]:
        return content_list, 200

    warnings = []

    email_policy = content["policy"]["emailRule"]
    if email_policy and email_policy != "allow":
        email_list = contains_emails(content_list)
        if email_policy == "block":
            block = should_block(email_list)
            if block:
                data = {
                    "action": "block"
                }

                return jsonify(data)
        elif email_policy == "allow_but_redact":
            redacted = redact(email_list, content_list)
            content_list = redacted
        elif email_policy == "allow_but_warn":
            warnings.append("email is found")

    ssn_policy = content["policy"]["ssnRule"]
    if ssn_policy and ssn_policy != "allow":
        ssn_list = contains_ssn(content_list)

        if ssn_policy == "block":
            block = should_block(ssn_list)
            if block:
                data = {
                    "action": "block"
                }

                return jsonify(data)
        elif ssn_policy == "allow_but_redact":
            redacted = redact(ssn_list, content_list)
            content_list = redacted
        elif ssn_policy == "allow_but_warn":
            warnings.append("ssn is found")

    regex_policy = content["policy"]["regularExpressionRules"]
    if regex_policy and len(regex_policy) != 0:
        for regex_config in regex_policy:
            regex = regex_config["definition"]
            action = regex_config["action"]
            regex_match_list = contains_regex_matches(regex, content_list)

            if action == "block":
                block = should_block(regex_match_list)
                if block:
                    data = {
                        "action": "block"
                    }

                    return jsonify(data)
            elif action == "allow_but_redact":
                redacted = redact(ssn_list, content_list)
            elif action == "allow_but_warn":
                warnings.append("regular rule {} matching found".format(regex))

    namePolicy = content["policy"]["nameRule"]
    if namePolicy and namePolicy != "allow":
        names = use_openai_extract_names(content_list)
        if namePolicy == "block":
            block = should_block(ssn_list)
            if block:
                data = {
                    "action": "block"
                }

                return jsonify(data)
        elif ssn_policy == "allow_but_redact":
            redacted = redact(ssn_list, content_list)
            content_list = redacted
        elif ssn_policy == "allow_but_warn":
            warnings.append("ssn is found")

    addressRule = content["policy"]["addressRule"]
    if addressRule:
        if addressRule != "allow":
            return content_list, 200

    return content_list, 200


if __name__ == '__main__':
    app.run(debug=True)


def contains_ssn(string_list):
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    result = []

    for text in string_list:
        ssns = re.findall(ssn_pattern, text)
        result.append(ssns)

    return result


def contains_emails(string_list):
    email_pattern = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    result = []

    for text in string_list:
        emails = re.findall(email_pattern, text)
        result.append(emails)

    return result


def redact(target_string_list, string_list):
    result = []

    updated = ""
    for idx, text in string_list:
        updated = text
        for target in target_string_list[idx]:
            updated = updated.replace(target, "***")

        result.append(updated)

    return result


def redact_names(name_list, string_list):
    result = []

    updated = ""
    for text in string_list:
        updated = text
        for target in name_list:
            updated = updated.replace(target, "***")

        result.append(updated)

    return result


def redact_addresses(address_list, string_list):
    result = []

    updated = ""
    for text in string_list:
        updated = text
        for target in address_list:
            updated = updated.replace(target, "***")

        result.append(updated)

    return result


def contains_regex_matches(regex, string_list):
    result = []

    for text in string_list:
        matched = re.findall(regex, text)
        result.append(matched)

    return result


def should_block(target_string_list):
    for text_list in target_string_list:
        if len(text_list) != 0:
            return False

    return True


def use_openai_extract_names(texts):
    names = []

    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant. You take in an array of strings and ouput JSON with one field called names. names field is an array of strings consisted of extracted people names from the given text.",
                },
                {
                    "role": "user",
                    "content": "[{}]".format(', '.join(texts)),
                }
            ],
            response_format={"type": "json_object"},
            model="gpt-4-1106-preview",
        )

        content = response.choices[0].message.content
        obj = json.loads(content)

        return obj["names"]

    except Exception as e:
        print(f"An error occurred: {e}")

    return names


def use_openai_extract_addresses(texts):
    addresses = []

    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant. You take in an array of strings and ouput JSON with one field called addresses. addresses field is an array of strings consisted of extracted physical addresses from the given text.",
                },
                {
                    "role": "user",
                    "content": "[{}]".format(', '.join(texts)),
                }
            ],
            response_format={"type": "json_object"},
            model="gpt-4-1106-preview",
        )

        content = response.choices[0].message.content
        obj = json.loads(content)

        return obj["addresses"]

    except Exception as e:
        print(f"An error occurred: {e}")

    return addresses


def use_openai_find_entities_using_custom_policies(texts, requirement):
    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant. You take in an array of strings and ouput JSON with one field called relevant_texts_found. relevant_texts_found is a boolean field that indicates whether or not given texts contain subtexts that fullfill the following requirements: {}".format(requirement),
                },
                {
                    "role": "user",
                    "content": "[{}]".format(', '.join(texts)),
                }
            ],
            response_format={"type": "json_object"},
            model="gpt-4-1106-preview",
        )

        content = response.choices[0].message.content
        obj = json.loads(content)

        return obj["relevant_texts_found"]

    except Exception as e:
        print(f"An error occurred: {e}")

    return False
