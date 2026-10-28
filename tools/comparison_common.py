"""Shared synthetic orders configuration and baseline transport predicate."""
import threading
import json
import re

SCHEMA = {'type':'object','properties':{'description':{'type':'string','maxBytes':256},'quantity':{'type':'integer','min':1,'max':1000}}}
COLLECTIONS = {'orders':{'schema':SCHEMA,'read_scope':'orders_read','write_scope':'orders_write','initial':'created','transitions':{'submit':{'from':'created','to':'submitted','scope':'orders_write'},'complete':{'from':'submitted','to':'completed','scope':'orders_write'}}}}


class BaselineQuota:
    """Independent fixed-window baseline policy; no distributed guarantees."""
    def __init__(self, capacity=10000):
        self.capacity=capacity
        self.windows={}
        self.lock=threading.Lock()

    def admit(self, subject, operation, now, requests=60, period=60):
        with self.lock:
            self.windows={k:v for k,v in self.windows.items() if v[0]+v[2]>now}
            pending=[]
            for key,limit,seconds in (((subject,None),60,60),((subject,operation),requests,period)):
                start,used,previous=self.windows.get(key,(now,0,seconds))
                if now>=start+max(seconds,previous): start,used,previous=now,0,seconds
                if used>=limit: return False
                if key not in self.windows and len(self.windows)+sum(k not in self.windows for k,_ in pending)>=self.capacity:
                    raise RuntimeError('rate capacity')
                pending.append((key,(start,used+1,max(seconds,previous))))
            self.windows.update(pending)
            return True


class BaselineCostBudget:
    """Independent bounded per-subject cost window for authenticated attempts."""
    def __init__(self, capacity=10000, limit=120, period=60):
        self.capacity,self.limit,self.period=capacity,limit,period
        self.windows={};self.lock=threading.Lock()

    def admit(self,subject,now):
        with self.lock:
            self.windows={k:v for k,v in self.windows.items() if v[0]+self.period>now}
            start,count=self.windows.get(subject,(now,0))
            if count>=self.limit:return False
            if subject not in self.windows and len(self.windows)>=self.capacity:raise RuntimeError('rate capacity')
            self.windows[subject]=(start,count+1)
            return True


def baseline_transport(path, sizes, media, transfer, encoding):
    """The JSON listener's transport gate, also usable without a socket."""
    return (path.startswith('/orders/') and media == ['application/json'] and
            transfer is None and encoding is None and len(sizes) == 1 and
            sizes[0].isdigit() and 1 <= int(sizes[0]) <= 65536)


def reconcile_create(response, record_id, intended_data):
    """Describe present state only; never infer that a particular write committed."""
    def valid_order(value):
        if type(value) is not dict or set(value)!={'description','quantity'} or type(value['description']) is not str or type(value['quantity']) is not int or not 1<=value['quantity']<=1000:
            return False
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',value['description']): return False
        try: return len(value['description'].encode('utf-8'))<=256
        except UnicodeEncodeError: return False
    if type(record_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}',record_id) or not valid_order(intended_data) or type(response) is not dict or response.get('ok') is not True:
        return 'unknown'
    data=response.get('data')
    if type(data) is not dict or set(data)!={'found','records'} or type(data['found']) is not bool or type(data['records']) is not list:
        return 'unknown'
    if data['found'] is False:
        return 'not_found' if data['records']==[] else 'unknown'
    if len(data['records'])!=1 or type(data['records'][0]) is not dict:
        return 'unknown'
    row=data['records'][0]
    if set(row)!={'id','version','phase','data'} or row['id']!=record_id or type(row['version']) is not int or not 1<=row['version']<=9007199254740991 or row['phase'] not in ('created','submitted','completed') or not valid_order(row['data']):
        return 'unknown'
    try:
        current=json.dumps(row['data'],sort_keys=True,separators=(',',':'),allow_nan=False)
        intended=json.dumps(intended_data,sort_keys=True,separators=(',',':'),allow_nan=False)
    except (TypeError,ValueError):
        return 'unknown'
    return 'current_matches_request' if current==intended else 'current_differs'
