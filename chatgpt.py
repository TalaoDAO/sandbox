
import json
from openai import OpenAI

# Remplace par ta clé API
api_key = json.load(open("keys.json", "r"))['openai']


client = OpenAI(
    # This is the default and can be omitted
    api_key=api_key
)

def analyze(vc):
    response = client.responses.create(
        model="gpt-4o",
        instructions="You are a serious coding assistant that talks like an expert of https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html",
        input="Here is the VC to analyze in sd-jwt format  " + vc + \
            "Can you: \
                1: provide the release of the sd-jwt VC specification used \
                2: verify that the type of VC is correct  \
                3: provide a resume of the content of this VC  \
                4: check that this VC respects the specifications of sd-jwt VC  \
                5: verify that the type of the Key Binding is correct  \
                6: list all errors or problems if any \
                7: mention the ChatGPT model used for this report"
    )
    return response.output_text