import uuid

LDP_PROOF_TYPE = [
    "JsonWebSignature2020",
    "Ed25519Signature2018",
    "EcdsaSecp256k1Signature2019",
    "RsaSignature2018"
]

JWT_ALG = [
    "ES256k",
    "ES256",
    "EdDSA"
]

class Presentation_Definition :

    def __init__(self, name, purpose, id=str(uuid.uuid1()) ):
        self.version = "0.1.1"
        self.pd = {
            "id": id,
            "input_descriptors": list(),
            "name" : name,
            "purpose" : purpose
        }
    
    def version(self):
        return self.version
    
    def add_format_ldp_vc(self,  proof_type=LDP_PROOF_TYPE) :
        if not self.pd.get('vc_formats'):
            self.pd['vc_formats'] = dict()
        self.pd["vc_formats"].update({
                "ldp_vc": {
                    "proof_type": proof_type
                }
            })
    
    def add_format_ldp_vp(self, proof_type=LDP_PROOF_TYPE) :
        if not self.pd.get('vp_formats') :
            self.pd['vp_formats'] = dict()
        self.pd["vp_formats"].update({
                "ldp_vp": {
                    "proof_type": proof_type
                }
            })
    
    def add_format_jwt_vc(self, jwt_alg=JWT_ALG) :
        if not self.pd.get('vc_formats') :
            self.pd['vc_formats'] = dict()
        self.pd["vc_formats"].update({
                "jwt_vc": {
                    "alg": jwt_alg
                }
            })
        
    def add_format_jwt_vc_ebsi(self, jwt_alg=JWT_ALG) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "jwt_vc": {
                    "alg": jwt_alg
                }
            })
        
    def add_format_jwt_vp(self, jwt_alg=JWT_ALG) :
        if not self.pd.get('vp_formats') :
            self.pd['vp_formats'] = dict()
        self.pd["vp_formats"].update({
                "jwt_vp": {
                    "alg": jwt_alg
                }
            })
        
        
    def add_format_jwt_vp_ebsi(self, jwt_alg=JWT_ALG) :
        if not self.pd.get('format') :
            self.pd['format'] = dict()
        self.pd["format"].update({
                "jwt_vp": {
                    "alg": jwt_alg
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


    def add_constraint_with_type_array(self, path, pattern, name, purpose, id= str(uuid.uuid1())) :
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
                                "type": "array",
                                "contains": {
                                    "const": pattern
                                }
                            }
                        }
                    ]
                }
            }
        )
        

    def add_filter(self, descriptor_id, path, pattern) :
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
        if pattern :
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
        else :
            self.pd['input_descriptors'].append(
                {   
                    "id" : id,
                    "group": [group],
                    "name" : name,
                    #"purpose" : purpose,
                    "constraints": {
                        "fields": [
                            {
                                "path": [path]
                            }
                        ]
                    }
                }
            )
    def add_constraint_with_group_and_schema(self, schema, name, purpose, group, id= str(uuid.uuid1())):
        self.pd['input_descriptors'].append(
                {   
                    "id" : id,
                    "group": [group],
                    "name" : name,
                    "schema" : [schema]
                }
            )
       

    def add_group(self, name, group, min=None, max= None, count=None, rule="pick"):
        if rule not in ['pick', 'all'] :
            return
        pattern = {
                    "name": name,
                    "rule": rule,
                    "from": group
                }
        if rule == "pick" :
            if count :
                pattern['count'] = count
            if not count :
                if min >= 0:
                    pattern['min'] = min
                if max :
                    pattern['max'] = max  
        if not self.pd.get("submission_requirements") :
            self.pd["submission_requirements"] = list()
        self.pd["submission_requirements"].append(pattern)

    def get(self):
        return self.pd




# MAIN entry point for test
if __name__ == '__main__':
  
    myprez = Presentation_Definition("test", "This a test")  
    #myprez.add_constraint("$.credentialSubject.firstName", "", "", "", id="descriptor_1")
    myprez.add_filter('descriptor_1', '$.credentialSubject.lastName', '')
    #myprez.add_constraint("$.credentialSubject.type", "VerifiableId", "", "")
    #myprez.add_group("test with group A", "A", min=1)
    #myprez.add_constraint_with_group_and_schema({'uri' : 'https:///www.com'}, "DbcPhonePass", "avec ID card", "A")
    #myprez.add_group("test with group B", "B")
    #myprez.add_constraint_with_group("$.credentialSubject.type", "PhonePass", "avec ID card", "Present and IOd Card", "A")
    #myprez.add_constraint_with_group("$.credentialSubject.type", "EmailPass", "avec Email pass", "Present a proof of email", "A")
    #myprez.add_format_ldp_vc()
    #myprez.add_format_ldp_vp()

    a = myprez.get()
    import json
    print(json.dumps(a, indent=4))


