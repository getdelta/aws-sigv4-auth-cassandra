"use strict";

import Cassandra from "cassandra-driver";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import sigv4 from "./lib/sigv4-auth-signature";

function extractNonce(buf: Buffer) {
  let bufAsString = buf.toString();
  let res1 = bufAsString.split("nonce=");

  if (res1.length < 2) {
    return undefined;
  }

  let res2 = res1[1].split(",");

  return res2[0];
}

class SigV4Authenticator implements Cassandra.auth.Authenticator {
  private region: string;
  private chain: ReturnType<typeof fromNodeProviderChain>;

  constructor(region: string, chain: ReturnType<typeof fromNodeProviderChain>) {
    this.region = region;
    this.chain = chain;
  }

  public initialResponse(callback: Function) {
    const responseBuffer = Buffer.from("SigV4\0\0", "utf8");
    callback(null, responseBuffer);
  }

  public evaluateChallenge(challenge: Buffer, callback: Function) {
    let nonce = extractNonce(challenge);

    if (!nonce) {
      callback(
        new Error(
          `[SIGV4_MISSING_NONCE] Did not find nonce in SigV4 challenge:[${challenge}]`
        ),
        null
      );
      return;
    }

    this.chain().then((credentials) => {
      let signedString = sigv4.computeSigV4SignatureCassandraRequest({
        region: this.region,
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
        sessionToken: credentials.sessionToken,
        date: new Date(),
        nonce,
      });

      callback(null, Buffer.from(signedString));
    });
  }

  public onAuthenticationSuccess(_token?: Buffer | undefined) {
    // noop
  }
}

class SigV4AuthProvider implements Cassandra.auth.AuthProvider {
  private region: string;

  constructor(region: string) {
    this.region = region;
  }

  public newAuthenticator(
    _endpoint: string,
    _name: string
  ): Cassandra.auth.Authenticator {
    return new SigV4Authenticator(this.region, fromNodeProviderChain());
  }
}

export default {
  SigV4AuthProvider,
  SigV4Authenticator,
};
