const { JWK, JWE } = require("node-jose");

require("pem-jwk");

const CONTENT_ALG = "A256GCM";
const ALG = "RSA-OAEP";
const FORMAT = "compact";
const JWK_RAW_KEY = "pem";
const FORM = "form";

createTestJWEString = () => {
  encrypt = async (
    obj,
    format = FORMAT,
    contentAlg = CONTENT_ALG,
    alg = ALG
  ) => {
    //PUBLIC HASH KEY

    let PUBLIC_HASH_KEY_EIL2_CPA =
      "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFsaHczTG5FYVp1aG1YUzRPY0JNRAozNjNPdjlUUE5KQm51aDB4cmtXajcrUjdBZmxqQVJ0ai84WDU2NWV1dEJydU1LYXpVdnNmVDBUbTdzTFNyUk15CjhOSUF5Y1QwajFYcmRIOGFTRVJzQjFiOGg4K1BvaVlxUU9nM3JtSERGeUdkeFYrYkFsOE1Od3Z0T3djYmVRTnUKUXVzWHhpd01GVWdHWG5Sc2VpNUtPQ0dyL1grbmVIZllwMzdaSlFrbnFhdkdGSjNrYzlDR0lLQmJmb080TWdjUwozdTg1ZVFxbytHRGJpYjVVVWV0SUFFTmpDcitwS091NVNlWUg4NThSTERKbExVb2VNOThSazd2NkNlb21lQUs1CkFlV2lpcFZXSEhUMVBqVmErU3V0VndwaGJYQ2xvM2RPc2xtcmdJSElhMUpDY3FPT2duYTk4YVVMaGJSOFh2UGYKelFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

    // DECODING BASE64

    let _publicKey = window.atob(PUBLIC_HASH_KEY_EIL2_CPA);
    let publicKey = await JWK.asKey(_publicKey, JWK_RAW_KEY);
    const buffer = Buffer.from(JSON.stringify(obj));
    const encrypted = await JWE.createEncrypt(
      { format: format, contentAlg: contentAlg, fields: { alg: alg } },
      publicKey
    )
      .update(buffer)
      .final();
    return encrypted;
  };
  let formDataArray = $(FORM).serializeArray();
  let obj = {};

  //BUILDING OBJECT FROM COLLECTED FORM DATA

  $.each(formDataArray, function (index, field) {
    obj[field.name] = field.value;
  });

  //ENCRYTPING THE OBJECT

  console.log(encrypt(obj));
};
