import assert from 'node:assert/strict';
import {expectedClass,classificationFailure} from './seeded-corpus-oracle.mjs';
for(const kind of ['valid','field_order','text_unicode','text_31','text_32','number_9','number_10','array_1','array_2']){
 assert.equal(expectedClass[kind],'normal');
 assert.equal(classificationFailure({kind,expectedClass:expectedClass[kind],observation:'rejected'}),'normalRejected',`${kind} rejection must count`);
 assert.equal(classificationFailure({kind,expectedClass:expectedClass[kind],observation:'accepted'}),'normalSemanticMismatch');
 assert.equal(classificationFailure({kind,expectedClass:expectedClass[kind]}),'normalUncertain');
}
for(const kind of ['text_33','number_11','array_3','duplicate_body'])assert.equal(classificationFailure({kind,expectedClass:expectedClass[kind]}),null);
assert.equal(classificationFailure({kind:'recovery',expectedClass:'normal'}),'normalUncertain');
assert.equal(classificationFailure({kind:'boundary',expectedClass:'normal',observation:'accepted'}),'normalSemanticMismatch');
console.log('fixed expected classes and negative-control accounting passed');
