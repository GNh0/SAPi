"""Bound line-oriented HTTP metadata independently of the bounded message body."""
from .errors import SapiError


class LimitedMetadataReader:
    def __init__(self,stream,limit=16384):
        self.stream,self.limit,self.metadata=stream,limit,0
    def readline(self,limit=-1):
        remaining=self.limit-self.metadata
        if remaining<=0:raise SapiError("transport_error")
        value=self.stream.readline(min(remaining+1,limit) if limit>=0 else remaining+1)
        self.metadata+=len(value)
        if self.metadata>self.limit:raise SapiError("transport_error")
        return value
    def read(self,amount=-1):return self.stream.read(amount)
    def readinto(self,buffer):return self.stream.readinto(buffer)
    def close(self):self.stream.close()
    def __getattr__(self,name):return getattr(self.stream,name)
