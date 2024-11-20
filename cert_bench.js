/**
 * Originally by https://github.com/mozkeeler
 * (https://gist.github.com/mozkeeler/a08d4c6910a23447e6f363df1e563738)
 * 
 * Modified to include some benchmarking code
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// How to run this file:
// 1. [obtain firefox source code]
// 2. [build/obtain firefox binaries]
// 3. run `[path to]/run-mozilla.sh [path to]/xpcshell \
//                                  [path to]/verify.js \
//                                  [path to]/chain.pem

// <https://developer.mozilla.org/en/XPConnect/xpcshell/HOWTO>
// <https://bugzilla.mozilla.org/show_bug.cgi?id=546628>
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;
const Cr = Components.results;

let { NetUtil } = Cu.import("resource://gre/modules/NetUtil.jsm", {});
let { Services } = Cu.import("resource://gre/modules/Services.jsm", {});
let { FileUtils } = Cu.import("resource://gre/modules/FileUtils.jsm", {});
let { Promise } = Cu.import("resource://gre/modules/Promise.jsm", {});

function pathToFile(path) {
    return new FileUtils.File(path);
}

function readFile(file) {
    let fstream = Cc["@mozilla.org/network/file-input-stream;1"]
        .createInstance(Ci.nsIFileInputStream);
    fstream.init(file, -1, 0, 0);
    let data = NetUtil.readInputStreamToString(fstream, fstream.available());
    fstream.close();
    return data;
}

function trustAsRoot(rootCert) {
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
    certdb.setCertTrustFromString(rootCert, "Cu,Cu,Cu");
}

function findCerts(pem) {
    const header = /-----BEGIN CERTIFICATE-----/;
    const footer = /-----END CERTIFICATE-----/;
    let lines = pem.split(/[\r\n]/);
    let certs = [];
    let currentCert = "";
    let addingCert = false;
    for (let line of lines) {
        if (line.match(header)) {
            addingCert = true;
            continue;
        }
        if (line.match(footer)) {
            addingCert = false;
            certs.push(currentCert);
            currentCert = "";
            continue;
        }
        if (addingCert) {
            currentCert += line;
        }
    }
    return certs;
}

function loadCerts(certsPath) {
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
    let pem = readFile(pathToFile(certsPath));
    let pemCerts = findCerts(pem);
    let certs = [];
    for (let pemCert of pemCerts) {
        try {
            let cert = certdb.constructX509FromBase64(pemCert);
            certs.push(cert);
        } catch (e) {
            dump("couldn't construct certificate: " + e + "\n");
        }
    }
    return certs;
}

class VerifyResult {
    constructor(resolve) {
        this.resolve = resolve;
    }

    verifyCertFinished(aPRErrorCode) {
        this.resolve(aPRErrorCode);
    }
}

async function verifyCert(cert, hostname, time, repeat) {
    const certificateUsageSSLClient         = 0x0001;
    const certificateUsageSSLServer         = 0x0002;
    const certificateUsageEmailSigner       = 0x0010;
    const certificateUsageVerifyCA          = 0x0100;
    const certificateUsageAnyCA             = 0x0800;
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
        
    let result;
    let durations = [];

    for (let i = 0; i < repeat; i++) {
        let start = Cu.now();
        result = await new Promise((resolve, reject) => {
            let result = new VerifyResult(resolve);
            certdb.asyncVerifyCertAtTime(
                cert,
                certificateUsageSSLServer,
                Ci.nsIX509CertDB.FLAG_LOCAL_ONLY,
                hostname,
                time, // (new Date()).getTime() / 1000,
                result,
            );
        });
        durations.push(Cu.now() - start);
    }

    dump(`result: ${result}`);
    for (const duration of durations) {
        let duration_micro_sec = Math.round(duration * 1000);
        dump(` ${duration_micro_sec}`)
    }
    dump("\n")

    return result
}

function spinMainThreadUntil(predicate) {
    let threadManager = Cc["@mozilla.org/thread-manager;1"]
        .getService(Ci.nsIThreadManager);
    let mainThread = threadManager.currentThread;

    while (!predicate()) {
        mainThread.processNextEvent(true);
    }
}

// Verify a given chain using only the roots provided, at a given time,
// repeating <repeat> times for benchmarking
if (arguments.length != 5) {
    throw "Usage: verify.js <roots.pem> <chain.pem> <domain> <time> <repeat>";
}

let rootsPath = arguments[0];
let certsPath = arguments[1];
let domain = arguments[2];
let time = Number(arguments[3]);
let repeat = Number(arguments[4]);

let roots = loadCerts(rootsPath);
let certs = loadCerts(certsPath);

// NOTE: we assume that all built-in roots have been removed
// see security/nss/lib/ckfw/builtins/certdata.txt
for (const root of roots) {
    trustAsRoot(root);
}

let cert = certs[0];
let exitCode;
let done = false;

verifyCert(cert, domain, time, repeat).then((result) => {
    exitCode = (result == 0 ? 1 : 0);
    done = true;
});

spinMainThreadUntil(function() { return done; });
quit(exitCode);
