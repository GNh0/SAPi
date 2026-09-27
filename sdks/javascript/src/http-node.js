import http from 'node:http';
import https from 'node:https';
import {SapiError} from './errors.js';

// Native transport for Node versions without fetch. TLS uses Node's trusted CAs and hostname checks.
export function exchangeNode(address, wire, timeout) {
  return new Promise((resolve,reject) => {
    const transport = address.protocol === 'https:' ? https : http;
    let settled = false, timer;
    const fail = () => {if (!settled) {settled=true;clearTimeout(timer);reject(new SapiError('transport_error'));} request.destroy();};
    const request = transport.request(address,{method:'POST',maxHeaderSize:16384,headers:{'Content-Type':'application/sapi+jwe',Accept:'application/sapi+jwe','Content-Length':Buffer.byteLength(wire),Connection:'close'}},response => {
      if (response.statusCode !== 200 || response.headers['content-type']?.split(';')[0] !== 'application/sapi+jwe' || response.headers['content-encoding']) {fail();response.destroy();return;}
      const chunks=[];let size=0;
      response.on('data',chunk => {size+=chunk.length;if(size>131072) {fail();response.destroy();return;}chunks.push(chunk);});
      response.on('error',fail);response.on('aborted',fail);
      response.on('end',() => {
        if(settled) return;
        const data=Buffer.concat(chunks);
        if(!response.complete || (response.headers['content-length']!==undefined && Number(response.headers['content-length'])!==size) || data.some(b=>b>127)) {fail();return;}
        settled=true;clearTimeout(timer);resolve(data.toString('ascii'));
      });
    });
    request.on('error',fail);timer=setTimeout(fail,timeout);request.end(wire,'ascii');
  });
}
