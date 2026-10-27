"""Shared synthetic orders configuration and baseline transport predicate."""

SCHEMA = {'type':'object','properties':{'description':{'type':'string','maxBytes':256},'quantity':{'type':'integer','min':1,'max':1000}}}
COLLECTIONS = {'orders':{'schema':SCHEMA,'read_scope':'orders_read','write_scope':'orders_write','initial':'created','transitions':{'submit':{'from':'created','to':'submitted','scope':'orders_write'},'complete':{'from':'submitted','to':'completed','scope':'orders_write'}}}}


def baseline_transport(path, sizes, media, transfer, encoding):
    """The JSON listener's transport gate, also usable without a socket."""
    return (path.startswith('/orders/') and media == ['application/json'] and
            transfer is None and encoding is None and len(sizes) == 1 and
            sizes[0].isdigit() and 1 <= int(sizes[0]) <= 65536)
