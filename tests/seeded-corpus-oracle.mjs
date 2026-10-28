// Fixed expectation classes; replay cases include an initial valid operation.
export const expectedClass=Object.freeze({
 valid:'normal',invalid_schema:'reject',forbidden:'reject',scope:'reject',tampered:'reject',ciphertext:'reject',wrong_key:'reject',direction:'reject',service:'reject',base64_padding:'reject',short_iv:'reject',short_tag:'reject',replay:'normal',concurrent_replay:'normal',business_retry:'normal',invalid_output:'reject',store_error:'reject',d1_policy:'reject',duplicate_header:'reject',duplicate_body:'reject',invalid_utf8:'reject',lone_surrogate:'reject',extra_field:'reject',expired:'reject',field_order:'normal',text_sql:'normal',text_unicode:'normal',text_email:'normal',text_31:'normal',text_32:'normal',text_33:'reject',number_9:'normal',number_10:'normal',number_11:'reject',array_1:'normal',array_2:'normal',array_3:'reject',
});
export function classificationFailure(current){
 if(current?.expectedClass!=='normal')return null;
 if(current.observation==='rejected')return 'normalRejected';
 if(current.observation==='accepted')return 'normalSemanticMismatch';
 return 'normalUncertain';
}
