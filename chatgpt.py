
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
        instructions="You are a coding assistant that talks like an expert of https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html",
        input="Here is my VC in sd-jwt format  " + vc + \
            "Can you give me \
                1: a resume of the content of this VC in 5 lines maximum \
                2: check that this VC respects the specifications of sd-jwt VC ? \
                si il y a des erreurs il faut faire une liste des points qui ne sont pas respectés ?"
    )
    return response.output_text