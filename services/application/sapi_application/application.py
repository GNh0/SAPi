"""A declarative application API: no request-selected SQL, URL, command or code."""
import copy
from sapi import SecureServer,Schema
from sapi.constants import NAME
from sapi.egress import Egress


class Application:
    def __init__(self,codec,state,records,collections,targets=None,*,egress_ca=None):
        if type(collections) is not dict or len(collections)>64 or type(targets or {}) is not dict or len(targets or {})>64:raise ValueError("bounded application manifest required")
        self.server = SecureServer(codec,state)
        self.records = records
        self.egress = Egress({k:{n:v for n,v in t.items() if n!="scope"} for k,t in (targets or {}).items()},ca_file=egress_ca)
        for name,value in copy.deepcopy(collections).items():
            if not isinstance(name,str) or not NAME.fullmatch(name) or len(name)>48 or type(value) is not dict or set(value)-{"schema","read_scope","write_scope","initial","write_phases","transitions"} or not {"schema","read_scope","write_scope"}<=value.keys():raise ValueError("declared collection required")
            payload = value["schema"];Schema(payload,root_object=True)
            initial = value.get("initial","created")
            write_phases = value.get("write_phases",[initial])
            transitions = value.get("transitions",{})
            if not isinstance(initial,str) or not NAME.fullmatch(initial) or type(write_phases) is not list or not 1<=len(write_phases)<=64 or any(not isinstance(v,str) or not NAME.fullmatch(v) for v in write_phases) or type(transitions) is not dict or len(transitions)>64:raise ValueError("bounded workflow required")
            record = {"type":"object","properties":{"id":{"type":"string","format":"identifier","minBytes":1,"maxBytes":64},"version":{"type":"integer","min":1},"phase":{"type":"string","format":"identifier","maxBytes":64},"data":payload}}
            items = {"type":"array","items":record,"maxItems":1}
            query = {"type":"object","properties":{"id":record["properties"]["id"]}}
            changed = {"type":"object","properties":{"changed":{"type":"boolean"},"records":items}}
            found = {"type":"object","properties":{"found":{"type":"boolean"},"records":items}}
            found_schema,changed_schema=Schema(found,root_object=True),Schema(changed,root_object=True)
            def getter(p,d,name=name,output=found_schema):return records.get(codec.service,name,p,d,output_schema=output)
            self.server.register(name+"_get",value["read_scope"],query,found,lambda p,d:True,getter)
            for kind in ("create","update","delete"):
                fields = dict(query["properties"])
                if kind!="create":fields["version"]=record["properties"]["version"]
                if kind!="delete":fields["data"]=payload
                def mutation(p,d,name=name,kind=kind,initial=initial,phases=tuple(write_phases),output=changed_schema):
                    return records.mutate(kind,codec.service,name,p,d,initial=initial,write_phases=phases,output_schema=output)
                self.server.register(name+"_"+kind,value["write_scope"],{"type":"object","properties":fields},changed,lambda p,d:True,mutation)
            for edge,rule in transitions.items():
                if not isinstance(edge,str) or not NAME.fullmatch(edge) or type(rule) is not dict or set(rule)!={"from","to","scope"} or any(not isinstance(v,str) or not NAME.fullmatch(v) for v in rule.values()):raise ValueError("declared workflow edge required")
                def transition(p,d,name=name,rule=rule,initial=initial,output=changed_schema):return records.mutate("transition",codec.service,name,p,d,initial=initial,write_phases=(),transition=rule,output_schema=output)
                self.server.register(name+"_"+edge,rule["scope"],{"type":"object","properties":{"id":record["properties"]["id"],"version":record["properties"]["version"]}},changed,lambda p,d:True,transition)
        for name,target in (targets or {}).items():
            if len(name)>48 or set(target)!={"origin","path","input","output","scope"}:raise ValueError("declared egress capability required")
            def fetch(p,d,name=name):return self.egress.fetch(name,d)
            self.server.register("fetch_"+name,target["scope"],target["input"],target["output"],lambda p,d:True,fetch,requests=10,period=60)

    def handle(self,wire):return self.server.handle(wire)
    def inventory(self):return self.server.inventory()
