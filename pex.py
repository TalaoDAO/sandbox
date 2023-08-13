import uuid

class Presentation_Definition :

    def __init__(self, name, purpose, id=str(uuid.uuid1()) ):
        self.pd = {
            "id": id,
            "input_descriptors": list(),
            "name" : name,
            "purpose" : purpose
        }
    
    def add_format_ldp_vc(self) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "ldp_vc": {
                    "proof_type": [
                        "JsonWebSignature2020",
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019",
                        "RsaSignature2018"
                    ]
                }
            })
    
    def add_format_ldp_vp(self) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "ldp_vp": {
                    "proof_type": [
                        "JsonWebSignature2020",
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019",
                        "RsaSignature2018"
                    ]
                }
            })
    
    def add_format_jwt_vc(self) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "jwt_vc": {
                    "alg": [
                        "ES256k",
                        "ES256",
                        "EdDSA"
                    ]
                }
            })
        
    def add_format_jwt_vp(self) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "jwt_vp": {
                    "alg": [
                        "ES256k",
                        "ES256",
                        "EdDSA"
                    ]
                }
            })

    def add_constraint(self, path, pattern, name, purpose, id= str(uuid.uuid1())) :
        if not pattern :
            self.pd['input_descriptors'].append(
            {   
                "id" : id,
                "name" : name,
                "purpose" : purpose,
                "constraints": {
                    "fields": [
                        {
                            "path": [path]
                        }
                    ]
                }
            }
            )
        else :
            self.pd['input_descriptors'].append(
                {   
                    "id" : id,
                    "name" : name,
                    "purpose" : purpose,
                    "constraints": {
                        "fields": [
                            {
                                "path": [path],
                                "filter": {
                                    "type": "string",
                                    "pattern": pattern
                                }
                            }
                        ]
                    }
                }
            )
        
    def add_filter(self, descriptor_id,path, pattern) :
        for desc in self.pd['input_descriptors'] :
            found = False
            if desc['id'] == descriptor_id :
                if pattern :
                    desc['constraints']['fields'].append(
                        {
                            "path": [path],
                            "filter": {
                                "type": "string",
                                "pattern": pattern
                            }
                        }
                    )
                else :
                    desc['constraints']['fields'].append(
                        {
                            "path": [path]
                        }
                    )
                found = True
                break
            if found :
                return True
    

    def add_constraint_with_group(self, path, pattern, name, purpose, group, id= str(uuid.uuid1())):
        self.pd['input_descriptors'].append(
            {   
                "id" : id,
                "group": [group],
                "name" : name,
                #"purpose" : purpose,
                "constraints": {
                    "fields": [
                        {
                            "path": [path],
                            "filter": {
                                "type": "string",
                                "pattern": pattern
                            }
                        }
                    ]
                }
            }
        )

    def add_group(self, name, group, count=1):
        self.pd["submission_requirements"]= [
                {
                    "name": name,
                    "rule": "pick",
                    "count": count,
                    "from": group
                }       
            ]

    def get(self):
        return self.pd



myprez = Presentation_Definition("test", "faire un test")  
myprez.add_constraint("$.credentialSubject.firstName", "", "", "", id="descriptor_1")
myprez.add_filter('descriptor_1', '$.credentialSubject.lastName', '')
#myprez.add_constraint("$.credentialSubject.type", "VerifiableId", "", "")
#myprez.add_group("test avec group A", "A")
#myprez.add_constraint_with_group("$.credentialSubject.type", "PhonePass", "avec ID card", "Present and IOd Card", "A")
#myprez.add_constraint_with_group("$.credentialSubject.type", "EmailPass", "avec Email pass", "Present a proof of email", "A")
#myprez.add_format_ldp_vc()
#myprez.add_format_ldp_vp()

a = myprez.get()


import json
print(json.dumps(a, indent=4))


